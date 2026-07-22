.PHONY: build test test-race vet integration stress clean \
	docker-binaries docker-build docker-up docker-down docker-logs

# cactus requires Go 1.27+ (built-in crypto/mldsa). Until 1.27 ships, the
# default is the gotip 1.27-devel toolchain; override with `make GO=go`
# once a 1.27 release is installed.
GO ?= gotip
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
# The cactus image does not build from source. cactus needs Go 1.27 for
# crypto/mldsa and there is no golang:1.27 image yet, so the binaries are
# cross-built here with gotip and copied into a slim runtime image.
# Sunlight has no such constraint and builds inside its own image.
COMPOSE ?= docker compose -f docker/compose.yaml

docker-binaries:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/cactus ./cmd/cactus
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/cactus-cli ./cmd/cactus-cli
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/cactus-keygen ./cmd/cactus-keygen

docker-build: docker-binaries
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
