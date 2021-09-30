package main

import (
	"flag"
	"log"
	"runtime"

	"github.com/aptogeo/reverseproxy/lib"
)

func main() {
	var listen string
	flag.StringVar(&listen, "listen", "", "host:port to listen on")

	var host string
	var forward string
	var forwardhost string
	flag.StringVar(&host, "host", "", "host")
	flag.StringVar(&forward, "forward", "", "url to forward on")
	flag.StringVar(&forwardhost, "forwardhost", "", "host rewrite header")

	var prefix string
	var allowcrossorigin bool
	var https bool
	var autocertdomain string
	var crtfile string
	var keyfile string
	var gomaxprocs int
	flag.StringVar(&prefix, "prefix", "", "prefix")
	flag.BoolVar(&allowcrossorigin, "allowcrossorigin", true, "allow cross origin")
	flag.BoolVar(&https, "https", false, "use https")
	flag.StringVar(&autocertdomain, "autocertdomain", "", "autocert domain")
	flag.StringVar(&crtfile, "crtfile", "", "crt file")
	flag.StringVar(&keyfile, "keyfile", "", "key file")
	flag.IntVar(&gomaxprocs, "gomaxprocs", 4, "maximum number of CPUs")

	flag.Parse()

	if listen == "" {
		log.Fatalln("missing required -listen argument")
	}
	if forward == "" {
		log.Fatalln("missing required -forward argument")
	}
	if forwardhost == "" {
		log.Fatalln("missing required -forwardhost argument")
	}
	if https {
		if autocertdomain == "" && (crtfile == "" || keyfile == "") {
			log.Fatalln("missing -autocertdomain or -crtfile and -keyfile arguments")
		}
	}

	runtime.GOMAXPROCS(gomaxprocs)

	// Reverse proxy
	var hostForwards []*lib.HostForward
	hostForwards = append(
		hostForwards, &lib.HostForward{
			Host:        host,
			Forward:     forward,
			ForwardHost: forwardhost,
		},
	)

	rp := lib.NewReverseProxy(hostForwards, listen, prefix, allowcrossorigin)
	if https {
		if autocertdomain != "" {
			rp.UseAutocert(autocertdomain)
		}
		if crtfile != "" && keyfile != "" {
			rp.UseCertificate(crtfile, keyfile)
		}
	}

	if err := rp.Start(); err != nil {
		log.Fatalln(err)
	}
}
