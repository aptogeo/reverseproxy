
PRG = reverseproxy


build:
	@echo build
	@go get
	@go install

test:
	@echo test
	@go get
	go test lib/**

local: build
	@echo run
	$$GOPATH/bin/$(PRG) \
	-listen :8888 \
	-host "*" -forward  http://localhost:8090/ -forwardhost localhost:8090