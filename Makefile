.PHONY: build test lint clean

VERSION := $(shell cat VERSION 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o tiredvpn ./cmd/tiredvpn/

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o tiredvpn-linux-amd64 ./cmd/tiredvpn/

build-android:
	GOOS=android GOARCH=arm64 CGO_ENABLED=1 go build -buildmode=c-shared $(LDFLAGS) -o libtiredvpn.so ./cmd/tiredvpn/

test:
	go test -race ./internal/...

lint:
	golangci-lint run ./...

clean:
	rm -f tiredvpn tiredvpn-* libtiredvpn.so
