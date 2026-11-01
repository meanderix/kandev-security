.PHONY: build run test test-backend test-ui test-package-verifier \
	test-release-version audit-dependencies check-format fmt vet \
	package package-host package-file verify-package verify-package-host clean

# Keep BIN and VERSION aligned with the manifest ID and version.
BIN := bin/kandev-security
VERSION := 0.14.4
STAGE := .build/stage
PKG_OUT := $(notdir $(BIN))-$(VERSION).tar.gz

# Build plugin-pack in the pinned SDK module so packaging uses the host's
# dependencies without adding the full Kandev backend dependency set here.
KANDEV_SDK := ../kandev/apps/backend

## Build the plugin binary for the host platform (development use). kandev
## itself always installs from `make package`/`package-host` output, not this.
build:
	mkdir -p bin
	go build -o $(BIN) ./server/...

## Build + run. Mainly for -race / manual smoke checks: kandev normally spawns
## this binary itself via the go-plugin handshake, so a manually-started
## process has nothing to talk to on the other end.
run: build
	./$(BIN)

test: test-backend test-ui test-package-verifier test-release-version

test-backend:
	go test ./server/... ./internal/...

test-ui:
	npm run test:ui

test-package-verifier:
	sh scripts/test-verify-package.sh

test-release-version:
	sh scripts/test-verify-release-version.sh

audit-dependencies:
	npm audit --audit-level=high

fmt:
	gofmt -l .

check-format:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

vet:
	go vet ./server/... ./internal/...

## Cross-compile server/plugin-<goos>-<goarch>[.exe] for every platform in
## manifest.yaml's runtime.executables, stage manifest.yaml + ui/ alongside
## them, and pack the tree into $(PKG_OUT) with
## github.com/kandev/kandev/cmd/plugin-pack (resolved via the `replace` in
## go.mod). Install the tarball via Settings > Plugins or curl -F package=@...
package:
	rm -rf $(STAGE)
	mkdir -p $(STAGE)/server
	cp manifest.yaml $(STAGE)/manifest.yaml
	cp -r ui $(STAGE)/ui
	GOOS=linux   GOARCH=amd64 go build -o $(STAGE)/server/plugin-linux-amd64       ./server
	GOOS=linux   GOARCH=arm64 go build -o $(STAGE)/server/plugin-linux-arm64       ./server
	GOOS=darwin  GOARCH=amd64 go build -o $(STAGE)/server/plugin-darwin-amd64      ./server
	GOOS=darwin  GOARCH=arm64 go build -o $(STAGE)/server/plugin-darwin-arm64      ./server
	GOOS=windows GOARCH=amd64 go build -o $(STAGE)/server/plugin-windows-amd64.exe ./server
	cd $(KANDEV_SDK) && go run ./cmd/plugin-pack -dir $(CURDIR)/$(STAGE) -out $(CURDIR)/$(PKG_OUT)
	rm -rf $(STAGE)
	@echo "Wrote $(PKG_OUT)"

## Package for the host platform only — faster local iteration than the full
## 5-platform `make package` (matches plugin-pack's -platform-only).
package-host:
	rm -rf $(STAGE)
	mkdir -p $(STAGE)/server
	cp manifest.yaml $(STAGE)/manifest.yaml
	cp -r ui $(STAGE)/ui
	go build -o $(STAGE)/server/plugin-$$(go env GOOS)-$$(go env GOARCH)$$(go env GOEXE) ./server
	cd $(KANDEV_SDK) && go run ./cmd/plugin-pack -dir $(CURDIR)/$(STAGE) -out $(CURDIR)/$(PKG_OUT) -platform-only
	rm -rf $(STAGE)
	@echo "Wrote $(PKG_OUT)"

## Build and validate the all-platform archive: plugin-pack checks the manifest;
## this additionally verifies checksums, expected binaries, and that development
## files do not leak into the plugin package.
verify-package: package
	@set -eu; \
		tmp="$$(mktemp -d)"; \
		trap 'rm -rf "$$tmp"' EXIT; \
		tar -xzf "$(PKG_OUT)" -C "$$tmp"; \
		sh scripts/verify-package.sh "$$tmp" full

## Faster equivalent for local/CI host-platform packaging.
verify-package-host: package-host
	@set -eu; \
		tmp="$$(mktemp -d)"; \
		trap 'rm -rf "$$tmp"' EXIT; \
		tar -xzf "$(PKG_OUT)" -C "$$tmp"; \
		sh scripts/verify-package.sh "$$tmp" host "$$(go env GOOS)-$$(go env GOARCH)"

## Print the archive name without building it. Release automation uses this
## after it validates the manifest and Makefile versions.
package-file:
	@printf '%s\n' "$(PKG_OUT)"

clean:
	rm -rf bin $(STAGE) $(notdir $(BIN))-*.tar.gz
