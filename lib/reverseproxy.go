package lib

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// StatusError struct
type StatusError struct {
	Cause error
	Code  int
}

// NewStatusError constructs StatusError
func NewStatusError(cause error, code int) *StatusError {
	return &StatusError{Cause: cause, Code: code}
}

// Error implements the error interface
func (e StatusError) Error() string {
	return e.Cause.Error()
}

// BeforeSend defines before send callback function
type BeforeSend func(*http.Request) (*http.Request, error)

// AfterReceive defines after receive callback function
type AfterReceive func(*http.Response) (*http.Response, error)

// ReverseProxy structure
type ReverseProxy struct {
	prefix           string
	forward          string
	client           *http.Client
	next             http.Handler
	beforeSendFunc   BeforeSend
	afterReceiveFunc AfterReceive
	allowCrossOrigin bool
}

// NewReverseProxy constructs ReverseProxy
func NewReverseProxy(forward string, prefix string, allowCrossOrigin bool) *ReverseProxy {
	rp := new(ReverseProxy)
	rp.SetForward(forward)
	rp.SetPrefix(prefix)
	rp.SetAllowCrossOrigin(allowCrossOrigin)
	// create http client
	rp.client = &http.Client{}
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

// SetPrefix sets prefix
func (rp *ReverseProxy) SetPrefix(prefix string) {
	rp.prefix = prefix
	if rp.prefix == "" {
		rp.prefix = "/"
	}
	if !strings.HasPrefix(rp.prefix, "/") {
		rp.prefix = "/" + rp.prefix
	}
	if !strings.HasSuffix(rp.prefix, "/") {
		rp.prefix = rp.prefix + "/"
	}
}

// SetForward sets forward
func (rp *ReverseProxy) SetForward(forward string) {
	rp.forward = forward
}

// SetAllowCrossOrigin sets forward
func (rp *ReverseProxy) SetAllowCrossOrigin(allowCrossOrigin bool) {
	rp.allowCrossOrigin = allowCrossOrigin
}

// SetNextHandler sets next handler for middleware use
func (rp *ReverseProxy) SetNextHandler(next http.Handler) {
	rp.next = next
}

// SetBeforeSendFunc sets BeforeSend callback function
func (rp *ReverseProxy) SetBeforeSendFunc(beforeSendFunc BeforeSend) {
	rp.beforeSendFunc = beforeSendFunc
}

// SetAfterReceiveFunc sets AfterReceive callback function
func (rp *ReverseProxy) SetAfterReceiveFunc(afterReceiveFunc AfterReceive) {
	rp.afterReceiveFunc = afterReceiveFunc
}

// ServeHTTP serves rest request
func (rp *ReverseProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	url := rp.forward
	requestURL := request.URL.String()
	idx := strings.Index(requestURL, "://")
	if idx != -1 {
		requestURL = requestURL[idx+3:]
	}
	re := regexp.MustCompile("(" + rp.prefix + ")([/\\?]?.*)?")
	submatch := re.FindStringSubmatch(requestURL)
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
	res, err := rp.SendRequestWithContext(request.Context(), request.Method, url, request.Body, request.Header)
	if err != nil {
		statusError, valid := err.(*StatusError)
		if valid {
			http.Error(writer, "Requesting server "+url+" error: "+err.Error(), statusError.Code)
		} else {
			http.Error(writer, "Requesting server "+url+" error: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	rp.write(writer, res)
	if err != nil {
		http.Error(writer, "Writing response error", http.StatusInternalServerError)
		return
	}
}

// SendRequest sends request
func (rp *ReverseProxy) SendRequest(method string, url string, body io.Reader, header http.Header) (*http.Response, error) {
	return rp.SendRequestWithContext(context.Background(), method, url, body, header)
}

// SendRequestWithContext sends request with context
func (rp *ReverseProxy) SendRequestWithContext(ctx context.Context, method string, url string, body io.Reader, header http.Header) (*http.Response, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	// Add request header
	for n, h := range header {
		for _, h := range h {
			req.Header.Add(n, h)
		}
	}
	if rp.beforeSendFunc != nil {
		// Call before send function
		req, err = rp.beforeSendFunc(req)
		if err != nil {
			return nil, err
		}
	}
	// Send
	return rp.client.Do(req)
}

func (rp *ReverseProxy) write(writer http.ResponseWriter, res *http.Response) error {
	var err error
	if rp.afterReceiveFunc != nil {
		// Call after receive function
		res, err = rp.afterReceiveFunc(res)
		if err != nil {
			return err
		}
	}
	// Add response header
	for h, v := range res.Header {
		for _, v := range v {
			writer.Header().Add(h, v)
		}
	}
	if rp.allowCrossOrigin {
		// Allow access origin
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, HEAD, TRACE, DELETE, PATCH, COPY, HEAD, LINK, OPTIONS")
	}
	// Set status
	writer.WriteHeader(res.StatusCode)
	// Copy body
	_, err = io.Copy(writer, res.Body)
	if err != nil {
		return err
	}
	return nil
}
