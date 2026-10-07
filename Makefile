.PHONY: build test test-race vet lint fmt integration stress clean \
	docker-build docker-up docker-down docker-logs

# cactus requires Go 1.27+ (built-in crypto/mldsa).
GO ?= go
BIN_DIR ?= bin

build:
	$(GO) build -o $(BIN_DIR)/cactus ./cmd/cactus
	$(GO) build -o $(BIN_DIR)/cactus-cli ./cmd/cactus-cli
	$(GO) build -o $(BIN_DIR)/cactus-keygen ./cmd/cactus-keygen
	$(GO) build -o $(BIN_DIR)/cactus-pollinate ./cmd/cactus-pollinate

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# golangci-lint v2.13.0+ is needed to type-check a Go 1.27 module. CI
# pins the version in .github/workflows/ci.yml.
GOLANGCI_LINT ?= golangci-lint

lint:
	$(GOLANGCI_LINT) run

fmt:
	$(GOLANGCI_LINT) fmt

integration:
	$(GO) test -race -count=1 -tags=integration ./integration/...

# Bulk issuance stress test. Behind the `stress` build tag so it stays
# out of the normal suite. Defaults to 800 certificates; override with
# CACTUS_STRESS_CERTS / CACTUS_STRESS_CONCURRENCY.
stress:
	$(GO) test -race -count=1 -tags=stress -timeout 30m \
		-run TestBulkIssuanceStress -v ./integration/...

# --- docker-compose stack (cactus + Sunlight as a tlog-mirror) ---------
#
# Both images build from source inside Docker; see docker/README.md.
COMPOSE ?= docker compose -f docker/compose.yaml

docker-build:
	$(COMPOSE) build

docker-up: docker-build
	$(COMPOSE) up -d
	$(COMPOSE) ps

docker-down:
	$(COMPOSE) down -v

docker-logs:
	$(COMPOSE) logs -f

clean:
	rm -rf $(BIN_DIR)
