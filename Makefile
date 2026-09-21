BIN     := bin/scheck
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/b87/scheck/internal/version.Version=$(VERSION)

.PHONY: build test lint vet fix depcheck check integ live fixtures clean

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

# agent, policy, check, finding and report must not depend on any provider
# adapter or SDK (docs/SPEC.md §5.1).
depcheck:
	./scripts/depcheck.sh

check: vet fix lint depcheck test

# Integration tests need docker or podman; see test/containers.
integ:
	go test -tags integration -count=1 ./test/...

# Opt-in live tests: spend real money against the configured provider.
# SCHECK_LIVE=1 and OPENAI_API_KEY (or SCHECK_LIVE_BASE_URL) are required.
live:
	SCHECK_LIVE=1 go test -tags live -count=1 -v ./test/live/

# The R3 pre-flight recall probe (docs/ROADMAP-RESEARCH.md): needs
# TYPESAFE_API_KEY, spends a fraction of a cent, sends recorded fixture data only.
probe:
	SCHECK_LIVE=1 go test -tags live -count=1 -v -run TestJevVendorRecallProbe ./test/live/

# Re-record testdata/fixtures/{ubuntu,fedora} from the containers in test/containers.
fixtures:
	SCHECK_RECORD=1 go test -tags integration -count=1 -run TestRecordFixtures ./test/integ/

clean:
	rm -rf bin
