package lib

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

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
	return e.Message
}

// BeforeSend defines before send callback function
type BeforeSend func(*ReverseProxy, http.ResponseWriter, *http.Request, string) error

// AfterReceive defines after receive callback function
type AfterReceive func(*ReverseProxy, http.ResponseWriter, *http.Request, *http.Response) error

// ReverseProxy structure
type ReverseProxy struct {
	Listen           string
	Prefix           string
	Forward          string
	Host             string
	Https            bool
	AllowCrossOrigin bool
	client           *http.Client
	beforeSendFunc   BeforeSend
	afterReceiveFunc AfterReceive
	crtFile          string
	keyFile          string
}

// NewReverseProxy constructs ReverseProxy
func NewReverseProxy(listen string, forward string, host string, prefix string, allowCrossOrigin bool) *ReverseProxy {
	rp := new(ReverseProxy)
	rp.Listen = listen
	rp.Forward = forward
	rp.Host = host
	rp.Prefix = prefix
	rp.AllowCrossOrigin = allowCrossOrigin
	rp.Https = false
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

// SetBeforeSendFunc sets BeforeSend callback function
func (rp *ReverseProxy) SetBeforeSendFunc(beforeSendFunc BeforeSend) {
	rp.beforeSendFunc = beforeSendFunc
}

// SetAfterReceiveFunc sets AfterReceive callback function
func (rp *ReverseProxy) SetAfterReceiveFunc(afterReceiveFunc AfterReceive) {
	rp.afterReceiveFunc = afterReceiveFunc
}

// UseHttps uses Https with certificate
func (rp *ReverseProxy) UseHttps(crtFile string, keyFile string) {
	rp.Https = true
	rp.crtFile = crtFile
	rp.keyFile = keyFile
}

func (rp *ReverseProxy) Start() error {
	log.Println("Start server with:", "Listen=", rp.Listen, "Forward=", rp.Forward, "Host=", rp.Host, "Prefix=", rp.Prefix, "AllowCrossOrigin=", rp.AllowCrossOrigin, "Https=", rp.Https, "CrtFile=", rp.crtFile, "KeyFile=", rp.keyFile)
	if rp.Https {
		http.HandleFunc("/", rp.serveHTTP)
		return http.ListenAndServeTLS(rp.Listen, rp.crtFile, rp.keyFile, nil)
	}
	http.HandleFunc("/", rp.serveHTTP)
	return http.ListenAndServe(rp.Listen, nil)
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
	url := rp.Forward
	incomingRequestURL := incomingRequest.URL.String()
	incomingHost := incomingRequest.Host
	idx := strings.Index(incomingRequestURL, "://")
	if idx != -1 {
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
	}
	response, err := rp.SendRequestWithContext(incomingRequest.Context(), writer, incomingHost, incomingRequest.Method, url, incomingRequest.Body, incomingRequest.Header)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		rp.writeError(writer, err, incomingHost)
		return
	}
	rp.writeResponse(writer, incomingRequest, response, incomingHost)
}

// SendRequestWithContext sends request with context
func (rp *ReverseProxy) SendRequestWithContext(ctx context.Context, writer http.ResponseWriter, incomingHost string, method string, url string, body io.Reader, header http.Header) (*http.Response, error) {
	// Create request
	var request *http.Request
	var err error
	if method == "PUT" || method == "POST" || method == "PATCH" {
		request, err = http.NewRequestWithContext(ctx, method, url, body)
	} else {
		request, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	// Set host
	request.Host = rp.Host
	// Add request header
	for h, vs := range header {
		for _, v := range vs {
			request.Header.Add(h, v)
		}
	}
	if rp.beforeSendFunc != nil {
		// Call before send function
		err := rp.beforeSendFunc(rp, writer, request, incomingHost)
		if err != nil {
			return nil, err
		}
	}
	// Send
	return rp.client.Do(request)
}

func (rp *ReverseProxy) writeResponse(writer http.ResponseWriter, request *http.Request, response *http.Response, incomingHost string) {
	if rp.afterReceiveFunc != nil {
		// Call after receive function
		err := rp.afterReceiveFunc(rp, writer, request, response)
		if err != nil {
			rp.writeError(writer, err, incomingHost)
			return
		}
	}
	if response.StatusCode == 302 {
		location, _ := response.Location()
		rp.writeError(writer, NewStatusError(location.String(), 302), incomingHost)
		return
	}
	// Write header
	rp.writeResponseHeader(writer, response.Header)
	// Set status
	writer.WriteHeader(response.StatusCode)
	// Copy body
	_, err := io.Copy(writer, response.Body)
	if err != nil {
		rp.writeError(writer, err, incomingHost)
	}
}

func (rp *ReverseProxy) writeError(writer http.ResponseWriter, err error, incomingHost string) {
	rp.writeResponseHeader(writer, nil)
	statusError, valid := err.(*StatusError)
	if valid {
		if statusError.Code == 302 {
			loc := statusError.Error()
			if u, err := url.Parse(statusError.Error()); err == nil {
				if u.Host == rp.Host {
					loc = rp.Prefix + u.Path
					loc = strings.ReplaceAll(loc, "//", "/")
					if u.ForceQuery || u.RawQuery != "" {
						loc += "?"
						loc += u.RawQuery
					}
					if u.Fragment != "" {
						loc += "#"
						loc += u.EscapedFragment()
					}
					if rp.Https {
						loc = "https://" + incomingHost + loc
					} else {
						loc = "http://" + incomingHost + loc
					}
				}
			}
			writer.Header().Set("Location", loc)
			writer.WriteHeader(302)
		} else {
			http.Error(writer, err.Error(), statusError.Code)
		}
	} else {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func (rp *ReverseProxy) writeResponseHeader(writer http.ResponseWriter, header http.Header) {
	// Add response header
	for h, vs := range header {
		for _, v := range vs {
			writer.Header().Add(h, v)
		}
	}
	if rp.AllowCrossOrigin {
		// Allow access origin
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, HEAD, TRACE, DELETE, PATCH, COPY, HEAD, LINK, OPTIONS")
	}
}
