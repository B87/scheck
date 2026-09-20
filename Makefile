BIN     := bin/scheck
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/b87/scheck/internal/version.Version=$(VERSION)

.PHONY: build test lint vet check integ fixtures clean

build:
	go build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/scheck

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

check: vet lint test

# Integration tests need docker or podman; see test/containers.
integ:
	go test -tags integration -count=1 ./test/...

# Re-record fixture targets from the containers in test/containers.
fixtures:
	./test/containers/record.sh

clean:
	rm -rf bin
