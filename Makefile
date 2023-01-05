.PHONY: build

build:
	cd services/apiserver/cmd && go build -o ../../../bin/apiserver

.PHONY: test
test:
	cd services/apiserver/tests && go test -v -race -timeout 30s ./...

.DEFAULT_GOAL := build