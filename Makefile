
PRG = reverseproxy


build:
	@echo build
	@go install

test:
	@echo test
	go test lib/**
	go test token/**

run: build
	@echo run
	$$GOPATH/bin/$(PRG) \
	-listen 0.0.0.0:80 \
	-host localhost -forward  http://www.aptogeo.fr/ -forwardhost www.aptogeo.fr