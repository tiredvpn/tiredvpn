# Build stage
FROM golang:1.26-alpine AS builder

ARG VERSION=dev

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /tiredvpn ./cmd/tiredvpn/

# Prepare fake web root for anti-probe masquerade
RUN mkdir -p /var/www/html && \
    echo '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to nginx!</h1></body></html>' \
    > /var/www/html/index.html

# Runtime image (tun) — alpine variant with a shell for in-container
# debugging. NAT/forwarding for server TUN mode (-ip-pool) is configured by
# the binary itself via netlink/nftables (see internal/tun/nat_linux.go), not
# by this image — functionally this is the same as the scratch image below;
# use it only when you want `sh`/coreutils available for troubleshooting.
# Placed before the scratch stage (not last) so a target-less `docker build .`
# - what CI's build-push-action uses for the published `latest`/version tags -
# picks the minimal scratch image by default, not this one.
FROM alpine:3.20 AS tun

LABEL org.opencontainers.image.title="TiredVPN (TUN)" \
      org.opencontainers.image.description="DPI-resistant VPN for censored networks — alpine variant with a debug shell" \
      org.opencontainers.image.url="https://github.com/tiredvpn/tiredvpn" \
      org.opencontainers.image.source="https://github.com/tiredvpn/tiredvpn" \
      org.opencontainers.image.licenses="AGPL-3.0"

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /tiredvpn /usr/local/bin/tiredvpn

# Fake web root for anti-probe masquerade
COPY --from=builder /var/www/html/index.html /var/www/html/index.html

EXPOSE 443/tcp 443/udp 995/tcp 995/udp

ENTRYPOINT ["/usr/local/bin/tiredvpn"]

# Runtime image — scratch for zero OS attack surface. Last stage = the
# default a target-less `docker build .` produces, which is what CI publishes
# as tiredvpn/tiredvpn:latest / :<version>.
FROM scratch

LABEL org.opencontainers.image.title="TiredVPN" \
      org.opencontainers.image.description="DPI-resistant VPN for censored networks" \
      org.opencontainers.image.url="https://github.com/tiredvpn/tiredvpn" \
      org.opencontainers.image.source="https://github.com/tiredvpn/tiredvpn" \
      org.opencontainers.image.licenses="AGPL-3.0"

# CA certs for TLS connections to external hosts
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=builder /tiredvpn /tiredvpn

# Fake web root for anti-probe masquerade
COPY --from=builder /var/www/html/index.html /var/www/html/index.html

# 443/tcp — TLS (main listener)
# 443/udp — QUIC (UDP transport)
# 995/tcp  — IPv6 TLS listener (default -listen-v6)
# 995/udp  — IPv6 QUIC listener
EXPOSE 443/tcp 443/udp 995/tcp 995/udp

ENTRYPOINT ["/tiredvpn"]
