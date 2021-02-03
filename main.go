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
	flag.StringVar(&forward, "forward", "http://www.aptogeo.fr/", "host:port to forward on")
	flag.BoolVar(&allowCrossOrigin, "allowCrossOrigin", true, "allow cross origin")
	flag.Parse()
	log.Println("Listen:", listen, "Forward:", forward, "AllowCrossOrigin:", allowCrossOrigin)
	reverseProxy := lib.NewReverseProxy(forward, allowCrossOrigin)
	reverseProxy.SetBeforeSendFunc(func(req *http.Request) (*http.Request, error) {
		log.Print(req.URL.String())
		return req, nil
	})
	http.HandleFunc("/", reverseProxy.ServeHTTP)
	http.ListenAndServe(listen, nil)
}
