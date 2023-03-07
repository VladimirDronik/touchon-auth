.PHONY: build

build:
	cd cmd && go build -o ../../../bin/touchon_auth

.PHONY: test
test:
	cd services/apiserver/tests && go test -v -race -timeout 30s ./...

.DEFAULT_GOAL := build