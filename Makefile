
PRG = reverseproxy


build:
	@echo build
	@go install

test:
	@echo test
	go test lib/**

local: build
	@echo run
	$$GOPATH/bin/$(PRG) \
	-listen localhost:8888 \
	-host localhost:8888 -forward  http://localhost:8081/ -forwardhost localhost:8081