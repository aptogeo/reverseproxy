package lib

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages
type contextKey string

// ReverseProxyFromContext retrives GisProxy from context
func ReverseProxyFromContext(ctx context.Context) *ReverseProxy {
	v := ctx.Value(contextKey("ReverseProxy"))
	if v == nil {
		return nil
	}
	return v.(*ReverseProxy)
}

// IncomingRequestFromContext retrives incoming request from context
func IncomingRequestFromContext(ctx context.Context) *http.Request {
	v := ctx.Value(contextKey("IncomingRequest"))
	if v == nil {
		return nil
	}
	return v.(*http.Request)
}

// IpFromContext retrives incoming request from context
func IpFromContext(ctx context.Context) string {
	v := ctx.Value(contextKey("Ip"))
	if v == nil {
		return ""
	}
	return v.(string)
}

// HostForward struct
type HostForward struct {
	Host             string       // Host
	Forward          string       // Url to forward on
	ForwardHost      string       // Optional host rewrite header
	BeforeSendFunc   BeforeSend   // Before send callback function
	AfterReceiveFunc AfterReceive // After receive callback function
}

// String implements string formatting
func (hf *HostForward) String() string {
	return fmt.Sprintf("HostForward(Host= %v Forward=%v ForwardHost=%v BeforeSendFunc=%v AfterReceiveFunc=%v)", hf.Host, hf.Forward, hf.ForwardHost, hf.BeforeSendFunc, hf.AfterReceiveFunc)
}

// StatusError struct
type StatusError struct {
	Message     string
	Code        int
	ContentType string
}

// NewStatusError constructs StatusError
func NewStatusError(message string, code int) *StatusError {
	return &StatusError{Message: message, Code: code}
}

// NewStatusErrorWithContentType constructs StatusError
func NewStatusErrorWithContentType(message string, code int, contentType string) *StatusError {
	return &StatusError{Message: message, Code: code, ContentType: contentType}
}

// Error implements the error interface
func (e *StatusError) Error() string {
	return fmt.Sprintf("%v (%v)", e.Message, e.Code)
}

// BeforeSend defines before send callback function
type BeforeSend func(http.ResponseWriter, *http.Request, *HostForward) error

// AfterReceive defines after receive callback function
type AfterReceive func(http.ResponseWriter, *http.Response, *HostForward) error

// ReverseProxy structure
type ReverseProxy struct {
	server           *http.Server
	client           *http.Client
	HostForwards     []*HostForward
	Prefix           string
	AllowCrossOrigin bool
	https            bool
	autocertdomain   string
	crtfile          string
	keyfile          string
}

// NewReverseProxy constructs ReverseProxy
func NewReverseProxy(hostForwards []*HostForward, listen string, prefix string, allowCrossOrigin bool) *ReverseProxy {
	rp := new(ReverseProxy)
	rp.server = &http.Server{Addr: listen, Handler: rp}
	rp.HostForwards = hostForwards
	rp.Prefix = prefix
	rp.AllowCrossOrigin = allowCrossOrigin
	rp.https = false
	// create http client
	rp.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 0,
	}
	rp.client.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	return rp
}

// UseCertificate uses Https with certificate
func (rp *ReverseProxy) UseCertificate(crtfile string, keyfile string) {
	rp.https = true
	rp.crtfile = crtfile
	rp.keyfile = keyfile
}

// UseHttps uses Https with autocert
func (rp *ReverseProxy) UseAutocert(autocertdomain string) {
	rp.https = true
	rp.autocertdomain = autocertdomain
	// create the autocert.Manager with domains and path to the cache
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(rp.autocertdomain),
	}
	rp.server.TLSConfig = &tls.Config{
		GetCertificate: certManager.GetCertificate,
	}
}

// Start starts server
func (rp *ReverseProxy) Start() error {
	log.Println("Start server")
	log.Println("HostForwards=", rp.HostForwards)
	log.Println("Listen=", rp.server.Addr)
	log.Println("Prefix=", rp.Prefix)
	log.Println("AllowCrossOrigin=", rp.AllowCrossOrigin)
	log.Println("https=", rp.https)
	if rp.https {
		log.Println("autocertdomain=", rp.autocertdomain)
		log.Println("crtfile=", rp.crtfile)
		log.Println("keyfile=", rp.keyfile)
	}
	if rp.https {
		rp.server.ListenAndServeTLS(rp.crtfile, rp.keyfile)
	}
	return rp.server.ListenAndServe()
}

// Stop stops server
func (rp *ReverseProxy) Stop(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return rp.server.Shutdown(ctx)
}

// ServeHTTP serves rest request
func (rp *ReverseProxy) ServeHTTP(writer http.ResponseWriter, incomingRequest *http.Request) {
	rp.checkPrefix()
	hostForward := rp.RetrieveHostForward(incomingRequest)
	for _, currentHostForward := range rp.HostForwards {
		if currentHostForward.Host == "*" || currentHostForward.Host == incomingRequest.Host {
			hostForward = currentHostForward
			break
		}
	}
	if hostForward == nil {
		rp.WriteError(writer, incomingRequest, errors.New("unknown host for "+incomingRequest.Host), nil)
		return
	}
	if forwardUrl, err := rp.ComputeForwardUrl(incomingRequest.URL.String(), hostForward); err != nil {
		rp.WriteError(writer, incomingRequest, err, nil)
		return
	} else {
		rp.Forward(writer, incomingRequest, forwardUrl, hostForward)
	}
}

// Forward forwards rest request
func (rp *ReverseProxy) Forward(writer http.ResponseWriter, incomingRequest *http.Request, forwardUrl string, hostForward *HostForward) {
	// Set GisProxy to context
	ctx := context.WithValue(incomingRequest.Context(), contextKey("ReverseProxy"), rp)
	// Set Ip to context
	ip := ""
	if incomingRequest != nil {
		ip = incomingRequest.Header.Get("X-Real-IP")
		if ip == "" {
			ip = incomingRequest.Header.Get("X-Forwarded-For")
		}
		if ip == "" {
			ip = strings.Split(incomingRequest.RemoteAddr, ":")[0]
		}
	}
	ctx = context.WithValue(ctx, contextKey("Ip"), ip)
	// Set IncomingRequest to context
	ctx = context.WithValue(ctx, contextKey("IncomingRequest"), incomingRequest)
	// Send
	response, err := rp.sendRequestWithContext(ctx, writer, hostForward, incomingRequest.Method, forwardUrl, incomingRequest.Body, incomingRequest.Header)
	if response != nil {
		if response.Body != nil {
			defer response.Body.Close()
		}
	} else {
		response = &http.Response{
			Request: incomingRequest,
		}
	}
	if hostForward.AfterReceiveFunc != nil {
		// Call after receive function
		if err := hostForward.AfterReceiveFunc(writer, response, hostForward); err != nil {
			if statusError, valid := err.(*StatusError); !valid || statusError.Code >= 400 {
				log.Println("After receive error", err, incomingRequest.URL)
			}
			rp.WriteError(writer, incomingRequest, err, nil)
			return
		}
	}
	if err != nil {
		rp.WriteError(writer, incomingRequest, err, nil)
		return
	}
	rp.WriteResponse(writer, incomingRequest, response)
}

// RetrieveHostForward retrieves hostForward
func (rp *ReverseProxy) RetrieveHostForward(incomingRequest *http.Request) *HostForward {
	var hostForward *HostForward
	for _, currentHostForward := range rp.HostForwards {
		if currentHostForward.Host == incomingRequest.Host {
			hostForward = currentHostForward
			break
		}
	}
	return hostForward
}

// ComputeForwardUrl computes rewrite url
func (rp *ReverseProxy) ComputeForwardUrl(incomingRequestURL string, hostForward *HostForward) (string, error) {
	url := hostForward.Forward
	idx := strings.Index(incomingRequestURL, "://")
	if idx != -1 && idx < 10 {
		incomingRequestURL = incomingRequestURL[idx+3:]
	}
	re := regexp.MustCompile("(" + rp.Prefix + ")([/\\?]?.*)?")
	submatch := re.FindStringSubmatch(incomingRequestURL)
	if len(submatch) == 0 {
		submatch = re.FindStringSubmatch(incomingRequestURL + "/")
		if len(submatch) == 0 {
			return "", errors.New("Prefix " + rp.Prefix + " not found in request")
		}
	}
	if len(submatch) >= 3 && submatch[2] != "" {
		if strings.HasSuffix(url, "/") {
			if strings.HasPrefix(submatch[2], "/") {
				url += submatch[2][1:]
			} else {
				url += submatch[2]
			}
		} else {
			if strings.HasPrefix(submatch[2], "/") {
				url += submatch[2]
			} else {
				url += "/" + submatch[2]
			}
		}
	}
	return url, nil
}

// checkPrefix checks prefix
func (rp *ReverseProxy) checkPrefix() {
	if rp.Prefix == "" {
		rp.Prefix = "/"
	}
	if !strings.HasPrefix(rp.Prefix, "/") {
		rp.Prefix = "/" + rp.Prefix
	}
	if !strings.HasSuffix(rp.Prefix, "/") {
		rp.Prefix = rp.Prefix + "/"
	}
	rp.Prefix = strings.ReplaceAll(rp.Prefix, "//", "/")
}

// RewriteHostQueryRequest computes rewrite query
func (rp *ReverseProxy) RewriteHostQueryRequest(request *http.Request) error {
	for _, currentHostForward := range rp.HostForwards {
		if currentHostForward.ForwardHost != "" {
			// Query
			request.URL.RawQuery = strings.ReplaceAll(request.URL.RawQuery, currentHostForward.Host, url.QueryEscape(currentHostForward.ForwardHost))
			request.URL.RawQuery = strings.ReplaceAll(request.URL.RawQuery, url.QueryEscape(currentHostForward.Host), url.QueryEscape(currentHostForward.ForwardHost))
		}
	}
	return nil
}

// RewriteHostResponseBody computes rewrite body
func (rp *ReverseProxy) RewriteHostResponseBody(response *http.Response) error {
	var byteBody []byte
	var reader io.ReadCloser
	var err error
	if response.Header.Get("Content-Encoding") == "gzip" {
		if reader, err = gzip.NewReader(response.Body); err != nil {
			return err
		}
		defer reader.Close()
	} else {
		reader = response.Body
	}
	if byteBody, err = ioutil.ReadAll(reader); err != nil {
		return err
	}
	if err = response.Body.Close(); err != nil {
		return err
	}
	for _, currentHostForward := range rp.HostForwards {
		if currentHostForward.ForwardHost != "" {
			re := regexp.MustCompile(regexp.QuoteMeta(currentHostForward.ForwardHost) + "([^:]{1}|$)")
			trimedPrefix := strings.TrimLeft(rp.Prefix, "/")
			byteBody = []byte(re.ReplaceAllString(string(byteBody), currentHostForward.Host+"$1"+trimedPrefix))
		}
	}
	body := ioutil.NopCloser(bytes.NewReader(byteBody))
	response.Body = body
	response.ContentLength = int64(len(byteBody))
	response.Header.Set("Content-Length", strconv.Itoa(len(byteBody)))
	response.Header.Del("Content-Encoding")
	return nil
}

// sendRequestWithContext sends request with context
func (rp *ReverseProxy) sendRequestWithContext(ctx context.Context, writer http.ResponseWriter, hostForward *HostForward, method string, url string, body io.Reader, header http.Header) (*http.Response, error) {
	// Create request
	var request *http.Request
	var err error
	if method == "PUT" || method == "POST" || method == "PATCH" {
		request, err = http.NewRequestWithContext(ctx, method, url, body)
	} else {
		request, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		log.Println("New request error")
		return nil, err
	}
	// Add request header
	for h, vs := range header {
		for _, v := range vs {
			request.Header.Add(h, v)
		}
	}
	if hostForward.BeforeSendFunc != nil {
		// Call before send function
		err := hostForward.BeforeSendFunc(writer, request, hostForward)
		if err != nil {
			if statusError, valid := err.(*StatusError); !valid || statusError.Code >= 400 {
				log.Println("Before send error", err, request.URL)
			}
			return nil, err
		}
	}
	// Send
	return rp.client.Do(request)
}

// WriteResponse writes response
func (rp *ReverseProxy) WriteResponse(writer http.ResponseWriter, request *http.Request, response *http.Response) {
	if response.StatusCode == 302 {
		location, _ := response.Location()
		rp.WriteError(writer, request, NewStatusError(location.String(), 302), response.Header)
		return
	}
	// Write header
	rp.WriteResponseHeader(writer, request, response.Header)
	// Set status
	writer.WriteHeader(response.StatusCode)
	// Copy body
	if _, err := io.Copy(writer, response.Body); err != nil {
		log.Println("Copy response error")
		rp.WriteError(writer, request, err, nil)
	}
}

// writeResponse writes error
func (rp *ReverseProxy) WriteError(writer http.ResponseWriter, request *http.Request, err error, header http.Header) {
	rp.WriteResponseHeader(writer, request, header)
	statusError, valid := err.(*StatusError)
	if valid {
		if statusError.Code == 200 {
			if statusError.ContentType != "" {
				writer.Header().Set("Content-Type", statusError.ContentType)
			} else {
				writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
			writer.WriteHeader(200)
			writer.Write([]byte(statusError.Message))
		} else if statusError.Code == 302 {
			loc := statusError.Message
			// Rewrite location
			loc = rp.RewriteLocation(loc)
			writer.Header().Set("Location", loc)
			writer.WriteHeader(302)
		} else {
			log.Println("Error", http.StatusInternalServerError, statusError.Message)
			if statusError.ContentType != "" {
				writer.Header().Set("Content-Type", statusError.ContentType)
			} else {
				writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
			writer.WriteHeader(statusError.Code)
			writer.Write([]byte(statusError.Message))
		}
	} else {
		log.Println("Error", http.StatusInternalServerError, err)
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte(err.Error()))
	}
}

// WriteResponseHeader writes response header
func (rp *ReverseProxy) WriteResponseHeader(writer http.ResponseWriter, request *http.Request, header http.Header) {
	// Add response header
	for h, vs := range header {
		for _, v := range vs {
			writer.Header().Add(h, v)
		}
	}
	if rp.AllowCrossOrigin {
		// Allow access origin
		origin := request.Header.Get("Origin")
		if origin != "" {
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Set("Access-Control-Allow-Credentials", "true")
			writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, HEAD, TRACE, DELETE, PATCH, COPY, HEAD, LINK, OPTIONS")
		} else {
			writer.Header().Set("Access-Control-Allow-Origin", "*")
			writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, HEAD, TRACE, DELETE, PATCH, COPY, HEAD, LINK, OPTIONS")
		}
	}
}

// RewriteLocation rewrites location
func (rp *ReverseProxy) RewriteLocation(location string) string {
	rewrited := ""
	if u, err := url.Parse(location); err == nil {
		path := rp.Prefix + u.Path
		path = strings.ReplaceAll(path, "//", "/")
		query := ""
		if u.ForceQuery || u.RawQuery != "" {
			query += "?"
			query += u.RawQuery
		}
		fragment := ""
		if u.RawFragment != "" {
			fragment = "#" + u.RawFragment
		} else if u.Fragment != "" {
			fragment = "#" + u.Fragment
		}
		host := u.Host
		for _, currentHostForward := range rp.HostForwards {
			if currentHostForward.ForwardHost != "" {
				// Host
				if host == currentHostForward.ForwardHost {
					host = currentHostForward.Host
				}
				// Query
				re := regexp.MustCompile(regexp.QuoteMeta(currentHostForward.ForwardHost) + "([^:]{1}|$)")
				reEscaped := regexp.MustCompile(regexp.QuoteMeta(url.QueryEscape(currentHostForward.ForwardHost)) + "([^:]{1}|$)")
				trimedPrefix := strings.TrimLeft(rp.Prefix, "/")
				query = re.ReplaceAllString(query, url.QueryEscape(currentHostForward.Host)+"$1"+trimedPrefix)
				query = reEscaped.ReplaceAllString(query, url.QueryEscape(currentHostForward.Host)+"$1"+trimedPrefix)
				// Fragment
				fragment = re.ReplaceAllString(fragment, url.QueryEscape(currentHostForward.Host)+"$1"+trimedPrefix)
				fragment = reEscaped.ReplaceAllString(fragment, url.QueryEscape(currentHostForward.Host)+"$1"+trimedPrefix)
			}
		}
		if u.Scheme != "" && host != "" {
			rewrited = u.Scheme + "://" + host + path + query + fragment
		} else {
			rewrited = path + query + fragment
		}
		if location != rewrited {
			log.Println("Location rewrited:", location, "->", rewrited)
		}
	}
	return rewrited
}
