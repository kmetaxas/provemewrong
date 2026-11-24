# provemewrong build and test targets.

BINARY  := provemewrong
PKG     := ./cmd/provemewrong
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

GO      ?= go

# CGO is forbidden: the binary must be pure Go and statically linked.
# Use := (not ?=) so a CGO_ENABLED=1 in the environment is ignored.
# Override explicitly if you must:  make build CGO_ENABLED=1
CGO_ENABLED := 0

.PHONY: build test test-race vet fmt lint clean install version help

## build: compile the binary into ./bin (static, CGO disabled)
build:
	@mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

## install: install into GOBIN (or GOPATH/bin)
install:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) install -trimpath -ldflags "$(LDFLAGS)" $(PKG)

## test: run the unit/integration test suite (CGO disabled)
test:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

## test-race: run tests under the race detector
## NOTE: the Go race detector itself requires cgo, so this target overrides
## the project's CGO=0 policy; it is a developer-only check, not part of the
## shipped binary.
test-race:
	CGO_ENABLED=1 $(GO) test -race ./...

## vet: static analysis
vet:
	$(GO) vet ./...

## fmt: check formatting (fix with make fmt-fix)
fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)

## fmt-fix: apply gofmt
fmt-fix:
	gofmt -w .

## lint: vet + formatting check
lint: vet fmt

## clean: remove build artifacts
clean:
	rm -rf bin

## version: print the version string baked into the binary
version:
	@echo $(VERSION)

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/^## //' | column -t -s:
