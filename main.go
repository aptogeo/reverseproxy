package main

import (
	"flag"
	"log"

	"github.com/aptogeo/reverseproxy/lib"
)

func main() {
	var listen string
	var forward string
	var host string
	var prefix string
	var https bool
	var allowCrossOrigin bool
	var crtFile string
	var keyFile string
	flag.StringVar(&listen, "listen", "0.0.0.0:80", "host:port to listen on")
	flag.StringVar(&forward, "forward", "http://www.aptogeo.fr/", "url to forward on")
	flag.StringVar(&host, "host", "www.aptogeo.fr", "host header for client request")
	flag.StringVar(&prefix, "prefix", "/", "prefix path")
	flag.BoolVar(&allowCrossOrigin, "allowCrossOrigin", true, "allow cross origin")
	flag.BoolVar(&https, "https", false, "use https")
	flag.StringVar(&crtFile, "crtFile", "", "crt file")
	flag.StringVar(&keyFile, "keyFile", "", "key file")
	flag.Parse()
	reverseProxy := lib.NewReverseProxy(listen, forward, host, prefix, allowCrossOrigin)
	if https {
		reverseProxy.UseHttps(crtFile, keyFile)
	}

	if err := reverseProxy.Start(); err != nil {
		log.Fatalln(err)
	}
}
