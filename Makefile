.PHONY: build build-linux build-android build-macos-cli build-macos-lib test lint clean

VERSION := $(shell cat VERSION 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

MACOS_BUILD_DIR := build/macos

build:
	go build $(LDFLAGS) -o tiredvpn ./cmd/tiredvpn/

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o tiredvpn-linux-amd64 ./cmd/tiredvpn/

build-android:
	GOOS=android GOARCH=arm64 CGO_ENABLED=1 go build -buildmode=c-shared $(LDFLAGS) -o libtiredvpn.so ./cmd/tiredvpn/

# Standalone macOS CLI binaries for debugging without the GUI app.
# Must be run on macOS (CGo + utun need the Darwin toolchain).
build-macos-cli:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o tiredvpn-macos-arm64 ./cmd/tiredvpn/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o tiredvpn-macos-amd64 ./cmd/tiredvpn/

# Universal c-archive consumed by the tiredvpn-macos Swift app.
# Produces $(MACOS_BUILD_DIR)/libtiredvpn.a + libtiredvpn.h (universal arm64+amd64).
# Requires: macOS host with Xcode CLT (clang, lipo).
build-macos-lib:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "ERROR: build-macos-lib must run on macOS (needs clang + lipo)"; exit 1; \
	fi
	mkdir -p $(MACOS_BUILD_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
		SDKROOT=$$(xcrun --sdk macosx --show-sdk-path) \
		go build $(LDFLAGS) -buildmode=c-archive \
		-o $(MACOS_BUILD_DIR)/libtiredvpn-arm64.a ./cmd/tiredvpn/
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
		SDKROOT=$$(xcrun --sdk macosx --show-sdk-path) \
		go build $(LDFLAGS) -buildmode=c-archive \
		-o $(MACOS_BUILD_DIR)/libtiredvpn-amd64.a ./cmd/tiredvpn/
	lipo -create \
		$(MACOS_BUILD_DIR)/libtiredvpn-arm64.a \
		$(MACOS_BUILD_DIR)/libtiredvpn-amd64.a \
		-output $(MACOS_BUILD_DIR)/libtiredvpn.a
	cp $(MACOS_BUILD_DIR)/libtiredvpn-arm64.h $(MACOS_BUILD_DIR)/libtiredvpn.h
	rm -f $(MACOS_BUILD_DIR)/libtiredvpn-arm64.a $(MACOS_BUILD_DIR)/libtiredvpn-amd64.a
	rm -f $(MACOS_BUILD_DIR)/libtiredvpn-arm64.h $(MACOS_BUILD_DIR)/libtiredvpn-amd64.h
	@echo "Built $(MACOS_BUILD_DIR)/libtiredvpn.a (universal)"
	@lipo -info $(MACOS_BUILD_DIR)/libtiredvpn.a

test:
	go test -race ./internal/...

lint:
	golangci-lint run ./...

clean:
	rm -f tiredvpn tiredvpn-* libtiredvpn.so
	rm -rf $(MACOS_BUILD_DIR)
