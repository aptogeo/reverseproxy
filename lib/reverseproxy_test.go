package lib_test

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aptogeo/reverseproxy/lib"
)

func echo(writer http.ResponseWriter, request *http.Request, hostForward *lib.HostForward) error {
	return lib.NewStatusError(request.URL.String(), 200)
}

func error500(writer http.ResponseWriter, request *http.Request, hostForward *lib.HostForward) error {
	return lib.NewStatusError("Error", 500)
}

func addHeader(writer http.ResponseWriter, response *http.Response, hostForward *lib.HostForward) error {
	writer.Header().Set("X-Test", strconv.Itoa(response.StatusCode))
	return nil
}

func TestReverseProxy(t *testing.T) {
	var hostForwards []*lib.HostForward
	hostForwards = append(
		hostForwards, &lib.HostForward{
			Host:             "localhost:8586",
			Forward:          "http://server.forward",
			ForwardHost:      "server.forward",
			BeforeSendFunc:   echo,
			AfterReceiveFunc: addHeader,
		},
	)
	rp := lib.NewReverseProxy(hostForwards, "localhost:8586", "/", true)
	defer rp.Stop(time.Second)
	go rp.Start()

	if response, err := http.Get("http://localhost:8586/path/to/resource/"); err != nil {
		t.Fatal(err)
	} else {
		if response.StatusCode != 200 {
			t.Fatal("Response 200 expected")
		}
		defer response.Body.Close()
		if body, err := ioutil.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		} else {
			received := strings.TrimSpace(string(body))
			expected := "http://server.forward/path/to/resource/"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
			received = response.Header.Get("X-Test")
			expected = "0"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
		}
	}
}

func TestReverseProxyWithPrefix(t *testing.T) {
	var hostForwards []*lib.HostForward
	hostForwards = append(
		hostForwards, &lib.HostForward{
			Host:             "localhost:8586",
			Forward:          "http://server.forward/forward/",
			ForwardHost:      "server.forward",
			BeforeSendFunc:   echo,
			AfterReceiveFunc: addHeader,
		},
	)
	rp := lib.NewReverseProxy(hostForwards, "localhost:8586", "/prefix", true)
	defer rp.Stop(time.Second)
	go rp.Start()

	if response, err := http.Get("http://localhost:8586/path/to/resource/"); err != nil {
		t.Fatal(err)
	} else if response.StatusCode != 500 {
		t.Fatal("Response 500 expected")
	} else {
		defer response.Body.Close()
		if body, err := ioutil.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		} else {
			received := strings.TrimSpace(string(body))
			expected := "Prefix /prefix/ not found in request"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
			received = response.Header.Get("X-Test")
			expected = "" // No X-Test header because after send function not called
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
		}
	}

	if response, err := http.Get("http://localhost:8586/prefix/path/to/resource/"); err != nil {
		t.Fatal(err)
	} else {
		if response.StatusCode != 200 {
			t.Fatal("Response 200 expected")
		}
		defer response.Body.Close()
		if body, err := ioutil.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		} else {
			received := strings.TrimSpace(string(body))
			expected := "http://server.forward/forward/path/to/resource/"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
			received = response.Header.Get("X-Test")
			expected = "0"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
		}
	}
}

func TestReverseProxyBeforeSendInError(t *testing.T) {
	var hostForwards []*lib.HostForward
	hostForwards = append(
		hostForwards, &lib.HostForward{
			Host:             "localhost:8586",
			Forward:          "http://server.forward",
			ForwardHost:      "server.forward",
			BeforeSendFunc:   error500,
			AfterReceiveFunc: addHeader,
		},
	)
	rp := lib.NewReverseProxy(hostForwards, "localhost:8586", "/", true)
	defer rp.Stop(time.Second)
	go rp.Start()

	if response, err := http.Get("http://localhost:8586/path/to/resource/"); err != nil {
		t.Fatal(err)
	} else {
		if response.StatusCode != 500 {
			t.Fatal("Error 500 expected")
		}
		defer response.Body.Close()
		if body, err := ioutil.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		} else {
			received := strings.TrimSpace(string(body))
			expected := "Error"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
			received = response.Header.Get("X-Test")
			expected = "0"
			if received != expected {
				t.Fatalf("Received %v; expexted %v", received, expected)
			}
		}
	}
}
