GO ?= go
GOFMT ?= $(if $(findstring /,$(GO)),$(dir $(GO))gofmt,gofmt)
GOOS ?= $(shell $(GO) env GOOS)

ifeq ($(GOOS),windows)
EXE_EXT := .exe
endif

.PHONY: build test lint verify-flags test-lab

build:
	mkdir -p dist
	$(GO) build -o dist/sec-server$(EXE_EXT) ./cmd/server
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	$(GO) build -o dist/sec-worker$(EXE_EXT) ./cmd/worker

test:
	$(GO) test -race ./...

lint:
	@command -v $(GOFMT) >/dev/null 2>&1 || { echo 'gofmt unavailable' >&2; exit 1; }
	@unformatted="$$( $(GOFMT) -l $$(find . -type f -name '*.go' -not -path './vendor/*'))"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	$(GO) vet ./...

verify-flags:
	@printf '%s\n' 'Blocked: pin the Nuclei and Trivy versions and implement their help-output checks before enabling engine flags.' >&2
	@printf '%s\n' 'Record the decision and verification evidence in docs/verification-log.md.' >&2
	@exit 2

test-lab:
	@if [ "$${LAB_ENV:-}" != "isolated" ]; then \
		printf '%s\n' 'Blocked: set LAB_ENV=isolated only after confirming this is a restricted lab environment.' >&2; \
		exit 2; \
	fi
	$(GO) test -tags=lab ./...
