
PRG = reverseproxy


build:
	@echo build
	@go install

test:
	@echo test
	go test lib/**

run: build
	@echo run
	$$GOPATH/bin/$(PRG) \
	-listen localhost:80 \
	-host localhost -forward  http://www.aptogeo.fr/ -forwardhost www.aptogeo.fr