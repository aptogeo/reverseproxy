package lib_test

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aptogeo/reverseproxy/lib"
)

func echo(rp *lib.ReverseProxy, writer http.ResponseWriter, request *http.Request, hostForward *lib.HostForward) error {
	return lib.NewStatusError(request.URL.String(), 200)
}

func TestReverseProxy(t *testing.T) {
	var hostForwards []*lib.HostForward
	hostForwards = append(
		hostForwards, &lib.HostForward{
			Host:             "localhost:8586",
			Forward:          "http://server.forward",
			ForwardHost:      "server.forward",
			BeforeSendFunc:   echo,
			AfterReceiveFunc: nil,
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
				t.Fatalf("received %v; expexted %v", received, expected)
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
			AfterReceiveFunc: nil,
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
				t.Fatalf("received %v; expexted %v", received, expected)
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
				t.Fatalf("received %v; expexted %v", received, expected)
			}
		}
	}
}
