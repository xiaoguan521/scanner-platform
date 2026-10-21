GO ?= go
GOFMT ?= $(if $(findstring /,$(GO)),$(dir $(GO))gofmt,gofmt)
GOOS ?= $(shell $(GO) env GOOS)

ifeq ($(GOOS),windows)
EXE_EXT := .exe
endif

.PHONY: build test lint verify-flags verify-deploy test-lab test-fence-lab web-install web-dev web-build dev dev-postgres test-local test-browser engines engines-zap engines-java test-engines-local migrate-postgres

dev:
	bash scripts/dev.sh

dev-postgres:
	@test -n "$${POSTGRES_DSN_FILE:-}" || { printf '%s\n' 'Set POSTGRES_DSN_FILE to an owner-only file containing the PostgreSQL DSN.' >&2; exit 2; }
	SCANNER_STORAGE=postgres SCANNER_POSTGRES_DSN_FILE="$${POSTGRES_DSN_FILE}" bash scripts/dev.sh

build:
	mkdir -p dist
	$(GO) build -o dist/sec-server$(EXE_EXT) ./cmd/server
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	$(GO) build -o dist/sec-worker$(EXE_EXT) ./cmd/worker
	$(GO) build -o dist/sec-fence-launcher$(EXE_EXT) ./cmd/fence-launcher
	$(GO) build -o dist/sec-worker-supervisor$(EXE_EXT) ./cmd/worker-supervisor
	$(GO) build -o dist/sec-portable$(EXE_EXT) ./cmd/portable

web-install:
	cd web && npm ci --ignore-scripts

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build


test:
	$(GO) test -race ./...
	PYTHONPATH=scripts python3 -m unittest scripts.test_collect_linux_inputs scripts.test_verify_compose_security scripts.test_workflow_contracts

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
	python3 scripts/install_engines.py --engine core
	$(GO) build -o dist/sec-updater$(EXE_EXT) ./cmd/updater
	./dist/sec-updater$(EXE_EXT) --prepare-engines
	$(MAKE) verify-flags

engines-zap:
	python3 scripts/install_engines.py --engine zap
	$(MAKE) verify-flags REQUIRE_ZAP=1

verify-flags:
	REQUIRE_ZAP=$(REQUIRE_ZAP) python3 scripts/verify_engine_flags.py

verify-deploy:
	@test -n "$${DEPLOY_COMPOSE_FILE:-}" || { printf '%s\n' 'Set DEPLOY_COMPOSE_FILE to the deployment Compose file to validate.' >&2; exit 2; }
	python3 scripts/verify_compose_security.py "$${DEPLOY_COMPOSE_FILE}"

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

test-fence-lab:
	@if [ "$${LAB_ENV:-}" != "isolated" ]; then \
		printf '%s\n' 'Blocked: set LAB_ENV=isolated only after confirming this is a restricted lab environment.' >&2; \
		exit 2; \
	fi
	@test "$(GOOS)" = linux || { printf '%s\n' 'test-fence-lab must run on Linux; cross-compile the Worker and test binary first.' >&2; exit 2; }
	@test -n "$${LAB_WORKER_BIN:-}" || { printf '%s\n' 'LAB_WORKER_BIN must point to the matching Linux sec-worker binary.' >&2; exit 2; }
	$(GO) test -tags=lab ./pocs/01 -run 'Test(IsolatedFenceInstall|FencedWorkerTask|FencedCgroupKillsDescendants)$$' -v

test-local: build web-build
	python3 scripts/test_local.py

test-browser: build web-build
	@if [ "$${LAB_ENV:-}" != "isolated" ]; then \
		printf '%s\n' 'Blocked: set LAB_ENV=isolated only after confirming this is a restricted lab environment.' >&2; \
		exit 2; \
	fi
	@test -n "$${SCANNER_E2E_BASE_URL:-}" || { printf '%s\n' 'SCANNER_E2E_BASE_URL is required (for example, the already running local Server URL).' >&2; exit 2; }
	@test -n "$${SCANNER_E2E_USERNAME:-}" || { printf '%s\n' 'SCANNER_E2E_USERNAME is required; no test account is created.' >&2; exit 2; }
	@test -n "$${SCANNER_E2E_PASSWORD:-}" || { printf '%s\n' 'SCANNER_E2E_PASSWORD is required; no password is stored.' >&2; exit 2; }
	@test -n "$${SCANNER_E2E_TARGET_IP:-}" || { printf '%s\n' 'SCANNER_E2E_TARGET_IP is required; use one explicitly authorized numeric IP.' >&2; exit 2; }
	test "$${SCANNER_E2E_CONFIRM:-}" = authorized || { printf '%s\n' 'Set SCANNER_E2E_CONFIRM=authorized after confirming the isolated target and port scope.' >&2; exit 2; }
	npm --prefix web run test:e2e

test-engines-local: build web-build
	LAB_ENV=isolated python3 scripts/test_engines_local.py

migrate-postgres: build
	@test -n "$${POSTGRES_DSN_FILE:-}" || { printf '%s\n' 'Set POSTGRES_DSN_FILE to an owner-only file containing the PostgreSQL DSN.' >&2; exit 2; }
	./dist/sec-server --migrate-postgres --postgres-dsn-file "$${POSTGRES_DSN_FILE}"
