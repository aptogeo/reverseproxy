
PRG = reverseproxy

build:
	@go install

run: build
	$$GOPATH/bin/$(PRG)
