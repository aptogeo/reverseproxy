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
)

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
	Message string
	Code    int
}

// NewStatusError constructs StatusError
func NewStatusError(message string, code int) *StatusError {
	return &StatusError{Message: message, Code: code}
}

// Error implements the error interface
func (e *StatusError) Error() string {
	return fmt.Sprintf("%v (%v)", e.Message, e.Code)
}

// BeforeSend defines before send callback function
type BeforeSend func(*ReverseProxy, http.ResponseWriter, *http.Request, *HostForward) error

// AfterReceive defines after receive callback function
type AfterReceive func(*ReverseProxy, http.ResponseWriter, *http.Response, *HostForward) error

// ReverseProxy structure
type ReverseProxy struct {
	server           *http.Server
	serverMux        *http.ServeMux
	client           *http.Client
	HostForwards     []*HostForward
	Prefix           string
	AllowCrossOrigin bool
	https            bool
	crtfile          string
	keyfile          string
}

// NewReverseProxy constructs ReverseProxy
func NewReverseProxy(hostForwards []*HostForward, listen string, prefix string, allowCrossOrigin bool) *ReverseProxy {
	rp := new(ReverseProxy)
	rp.serverMux = http.NewServeMux()
	rp.server = &http.Server{Addr: listen, Handler: rp.serverMux}
	rp.HostForwards = hostForwards
	rp.Prefix = prefix
	rp.AllowCrossOrigin = allowCrossOrigin
	rp.https = false
	// create http client
	rp.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

// UseHttps uses Https with certificate
func (rp *ReverseProxy) UseHttps(crtfile string, keyfile string) {
	rp.https = true
	rp.crtfile = crtfile
	rp.keyfile = keyfile
}

func (rp *ReverseProxy) Start() error {
	log.Println("Start server")
	log.Println("HostForwards=", rp.HostForwards)
	log.Println("Listen=", rp.server.Addr)
	log.Println("Prefix=", rp.Prefix)
	log.Println("AllowCrossOrigin=", rp.AllowCrossOrigin)
	log.Println("https=", rp.https)
	if rp.https {
		log.Println("crtfile=", rp.crtfile)
		log.Println("keyfile=", rp.keyfile)
	}
	rp.serverMux.HandleFunc("/", rp.serveHTTP)
	if rp.https {
		rp.server.ListenAndServeTLS(rp.crtfile, rp.keyfile)
	}
	return rp.server.ListenAndServe()
}

func (rp *ReverseProxy) Stop(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return rp.server.Shutdown(ctx)
}

// serveHTTP serves rest request
func (rp *ReverseProxy) serveHTTP(writer http.ResponseWriter, incomingRequest *http.Request) {
	if rp.Prefix == "" {
		rp.Prefix = "/"
	}
	if !strings.HasPrefix(rp.Prefix, "/") {
		rp.Prefix = "/" + rp.Prefix
	}
	if !strings.HasSuffix(rp.Prefix, "/") {
		rp.Prefix = rp.Prefix + "/"
	}
	var hostForward *HostForward
	for _, currentHostForward := range rp.HostForwards {
		if currentHostForward.Host == incomingRequest.Host {
			hostForward = currentHostForward
			break
		}
	}
	if hostForward == nil {
		rp.writeError(writer, incomingRequest, errors.New("unknown host"), nil)
		return
	}
	if url, err := rp.ComputeRewriteUrl(incomingRequest.URL.String(), hostForward); err != nil {
		rp.writeError(writer, incomingRequest, err, hostForward)
		return
	} else {
		response, err := rp.sendRequestWithContext(incomingRequest.Context(), writer, hostForward, incomingRequest.Method, url, incomingRequest.Body, incomingRequest.Header)
		if response != nil && response.Body != nil {
			defer response.Body.Close()
		}
		if err != nil {
			rp.writeError(writer, incomingRequest, err, hostForward)
			return
		}
		rp.writeResponse(writer, incomingRequest, response, hostForward)
	}
}

// ComputeRewriteUrl computes rewrite url
func (rp *ReverseProxy) ComputeRewriteUrl(incomingRequestURL string, hostForward *HostForward) (string, error) {
	url := hostForward.Forward
	idx := strings.Index(incomingRequestURL, "://")
	if idx != -1 && idx < 10 {
		incomingRequestURL = incomingRequestURL[idx+3:]
	}
	re := regexp.MustCompile("(" + rp.Prefix + ")([/\\?]?.*)?")
	submatch := re.FindStringSubmatch(incomingRequestURL)
	if submatch != nil && submatch[2] != "" {
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
	} else {
		return "", errors.New("Prefix " + rp.Prefix + " not found in request")
	}
	return url, nil
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
			byteBody = bytes.ReplaceAll(byteBody, []byte(currentHostForward.ForwardHost), []byte(currentHostForward.Host))
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
		err := hostForward.BeforeSendFunc(rp, writer, request, hostForward)
		if err != nil {
			statusError, valid := err.(*StatusError)
			if !valid || statusError.Code != 302 {
				log.Println("Before send error", err, request.URL)
			}
			return nil, err
		}
	}
	// Send
	return rp.client.Do(request)
}

// writeResponse writes response
func (rp *ReverseProxy) writeResponse(writer http.ResponseWriter, request *http.Request, response *http.Response, hostForward *HostForward) {
	if hostForward.AfterReceiveFunc != nil {
		// Call after receive function
		if err := hostForward.AfterReceiveFunc(rp, writer, response, hostForward); err != nil {
			statusError, valid := err.(*StatusError)
			if !valid || statusError.Code != 302 {
				log.Println("After receive error", err, request.URL)
			}
			rp.writeError(writer, request, err, hostForward)
			return
		}
	}
	if response.StatusCode == 302 {
		location, _ := response.Location()
		rp.writeError(writer, request, NewStatusError(location.String(), 302), hostForward)
		return
	}
	// Write header
	rp.writeResponseHeader(writer, request, response.Header)
	// Set status
	writer.WriteHeader(response.StatusCode)
	// Copy body
	if _, err := io.Copy(writer, response.Body); err != nil {
		log.Println("Copy response error")
		rp.writeError(writer, request, err, hostForward)
	}
}

// writeResponse writes error
func (rp *ReverseProxy) writeError(writer http.ResponseWriter, request *http.Request, err error, hostForward *HostForward) {
	rp.writeResponseHeader(writer, request, nil)
	statusError, valid := err.(*StatusError)
	if valid {
		if statusError.Code == 200 {
			writer.Write([]byte(statusError.Message))
		} else if statusError.Code == 302 {
			loc := statusError.Message
			// Rewrite location
			fragment := ""
			if strings.Contains(loc, "#") {
				strs := strings.Split(loc, "#")
				fragment = "#" + strs[1]
				loc = strs[0]
			}
			if u, err := url.Parse(loc); err == nil {
				path := rp.Prefix + u.Path
				path = strings.ReplaceAll(path, "//", "/")
				query := ""
				if u.ForceQuery || u.RawQuery != "" {
					query += "?"
					query += u.RawQuery
				}
				host := u.Host
				for _, currentHostForward := range rp.HostForwards {
					if currentHostForward.ForwardHost != "" {
						// Host
						host = strings.ReplaceAll(host, currentHostForward.ForwardHost, currentHostForward.Host)
						// Query
						u.RawQuery = strings.ReplaceAll(u.RawQuery, currentHostForward.ForwardHost, url.QueryEscape(currentHostForward.Host))
						u.RawQuery = strings.ReplaceAll(u.RawQuery, url.QueryEscape(currentHostForward.ForwardHost), url.QueryEscape(currentHostForward.Host))
						// Fragment
						fragment = strings.ReplaceAll(fragment, currentHostForward.ForwardHost, url.QueryEscape(currentHostForward.Host))
						fragment = strings.ReplaceAll(fragment, url.QueryEscape(currentHostForward.ForwardHost), url.QueryEscape(currentHostForward.Host))
					}
				}
				if u.Scheme != "" && host != "" {
					loc = u.Scheme + "://" + host + path + query + fragment
				} else {
					loc = path + query + fragment
				}
			}
			writer.Header().Set("Location", loc)
			writer.WriteHeader(302)
		} else {
			log.Println("Error", http.StatusInternalServerError, err)
			http.Error(writer, err.Error(), statusError.Code)
		}
	} else {
		log.Println("Error", http.StatusInternalServerError, err)
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

// writeResponseHeader writes response header
func (rp *ReverseProxy) writeResponseHeader(writer http.ResponseWriter, request *http.Request, header http.Header) {
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
