GO ?= go
GOFMT ?= $(if $(findstring /,$(GO)),$(dir $(GO))gofmt,gofmt)
GOOS ?= $(shell $(GO) env GOOS)

ifeq ($(GOOS),windows)
EXE_EXT := .exe
endif

.PHONY: build test lint verify-flags test-lab web-install web-dev web-build dev test-local engines engines-java test-engines-local

dev:
	bash scripts/dev.sh

build:
	mkdir -p dist
	$(GO) build -o dist/sec-server$(EXE_EXT) ./cmd/server
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	$(GO) build -o dist/sec-worker$(EXE_EXT) ./cmd/worker
	$(GO) build -o dist/sec-portable$(EXE_EXT) ./cmd/portable

web-install:
	cd web && npm ci --ignore-scripts

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build


test:
	$(GO) test -race ./...
	python3 -m unittest discover -s scripts -p 'test_collect_linux_inputs.py'

lint:
	@command -v $(GOFMT) >/dev/null 2>&1 || { echo 'gofmt unavailable' >&2; exit 1; }
	@unformatted="$$( $(GOFMT) -l $$(find . -type f -name '*.go' -not -path './vendor/*'))"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	$(GO) vet ./...

engines:
	mkdir -p dist
	python3 scripts/install_engines.py
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	./dist/sec-updater$(EXE_EXT) --prepare-engines
	$(MAKE) verify-flags

verify-flags:
	python3 scripts/verify_engine_flags.py

engines-java:
	mkdir -p dist
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	./dist/sec-updater$(EXE_EXT) --prepare-engines --with-java-db
	$(MAKE) verify-flags

test-lab:
	@if [ "$${LAB_ENV:-}" != "isolated" ]; then \
		printf '%s\n' 'Blocked: set LAB_ENV=isolated only after confirming this is a restricted lab environment.' >&2; \
		exit 2; \
	fi
	$(GO) test -tags=lab ./...

test-local: build web-build
	python3 scripts/test_local.py

test-engines-local: build web-build
	LAB_ENV=isolated python3 scripts/test_engines_local.py
