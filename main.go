package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/aptogeo/reverseproxy/lib"
)

func main() {
	var listen string
	var forward string
	var allowCrossOrigin bool
	flag.StringVar(&listen, "listen", "0.0.0.0:8080", "host:port to listen on")
	flag.StringVar(&forward, "forward", "http://www.aptogeo.fr:8181", "host:port to forward on")
	flag.BoolVar(&allowCrossOrigin, "allowCrossOrigin", false, "allow cross origin")
	log.Println("Listen:", listen, "Forward:", forward, "AllowCrossOrigin:", allowCrossOrigin)
	gisProxy := lib.NewReverseProxy(forward, allowCrossOrigin)
	gisProxy.SetBeforeSendFunc(func(req *http.Request) (*http.Request, error) {
		log.Println(req.URL.String())
		return req, nil
	})
	http.HandleFunc("/", gisProxy.ServeHTTP)
	http.ListenAndServe(listen, nil)
}
