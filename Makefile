BIN     := bin/scheck
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/b87/scheck/internal/version.Version=$(VERSION)

.PHONY: build test lint vet fix check integ fixtures clean

build:
	go build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/scheck

test:
	go test -race ./...

vet:
	go vet ./...

fix:
	go fix ./...
lint:
	golangci-lint run ./...

check: vet fix lint test

# Integration tests need docker or podman; see test/containers.
integ:
	go test -tags integration -count=1 ./test/...

# Re-record testdata/fixtures/{ubuntu,fedora} from the containers in test/containers.
fixtures:
	SCHECK_RECORD=1 go test -tags integration -count=1 -run TestRecordFixtures ./test/integ/

clean:
	rm -rf bin
