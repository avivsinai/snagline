SHELL := /bin/sh

GO ?= go
DOCKER ?= docker
GITLEAKS ?= gitleaks
PKG_CONFIG ?= pkg-config
BINDIR ?= bin
IMAGE_TARGET ?= control

CGO_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
CGO_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs-only-L openssl 2>/dev/null)
CGO_ENV := CGO_ENABLED=1 CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)"

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w

COMMANDS := snagline-control snagline-delivery snagline-edge snagline-front snagline-case snagline-dispatcher snagline-buzz-projector snagline-ssp-verify

.PHONY: fmt-check sqlcipher-toolchain verify-sqlcipher-build vet test verify-ssp verify-buzz-contract build docker-build secrets-scan clean verify

fmt-check:
	@unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -print0 | xargs -0 $(GO)fmt -l)"; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi

sqlcipher-toolchain:
	@command -v "$(PKG_CONFIG)" >/dev/null
	@"$(PKG_CONFIG)" --exists openssl

verify-sqlcipher-build:
	CGO_ENABLED=0 $(GO) test ./internal/sspedge -run '^TestOpenFailsClosedWithoutCGO$$' -count=1

vet: sqlcipher-toolchain
	$(CGO_ENV) $(GO) vet ./...

test: sqlcipher-toolchain
	$(CGO_ENV) $(GO) test ./...

verify-ssp:
	GO=$(GO) ./scripts/verify-ssp-vectors.sh

verify-buzz-contract:
	./deploy/buzz/test-stock-buzz-gate.sh

build: sqlcipher-toolchain
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-control ./cmd/snagline-control
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-delivery ./cmd/snagline-delivery
	$(CGO_ENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-edge ./cmd/snagline-edge
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-front ./cmd/snagline-front
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-case ./cmd/snagline-case
	$(CGO_ENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-dispatcher ./cmd/snagline-dispatcher
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-buzz-projector ./cmd/snagline-buzz-projector
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/snagline-ssp-verify ./cmd/snagline-ssp-verify

docker-build:
	$(DOCKER) build --target $(IMAGE_TARGET) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t snagline-$(IMAGE_TARGET):$(VERSION) .

secrets-scan:
	GITLEAKS=$(GITLEAKS) ./scripts/secrets-scan.sh tree

verify: fmt-check verify-sqlcipher-build vet test build verify-ssp verify-buzz-contract secrets-scan

clean:
	rm -rf $(BINDIR)
