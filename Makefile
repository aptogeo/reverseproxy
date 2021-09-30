
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
	-listen localhost:8080 \
	-host localhost:8080 -forward  http://www.aptogeo.fr/ -forwardhost www.aptogeo.fr