# TiredVPN

> A DPI-resistant VPN designed to work in heavily censored networks.

[![CI](https://github.com/tiredvpn/tiredvpn/actions/workflows/ci.yml/badge.svg)](https://github.com/tiredvpn/tiredvpn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tiredvpn/tiredvpn)](https://github.com/tiredvpn/tiredvpn/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/tiredvpn/tiredvpn)](https://hub.docker.com/r/tiredvpn/tiredvpn)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiredvpn/tiredvpn)](https://goreportcard.com/report/github.com/tiredvpn/tiredvpn)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/tiredvpn/tiredvpn)](go.mod)
![TiredVPN](img/github.png)

**Related repositories:** [tiredvpn/tiredvpn-android](https://github.com/tiredvpn/tiredvpn-android) — Android client

---

## What is TiredVPN?

TiredVPN is a censorship-resistant VPN that uses multiple bypass strategies to
establish and maintain connectivity in networks with active Deep Packet
Inspection (DPI). Instead of relying on a single obfuscation technique, it
implements an adaptive strategy engine that automatically selects the best
transport based on current network conditions.

The system probes available strategies, ranks them by latency and reliability,
and falls back to alternatives mid-session if the active strategy gets blocked.
This makes it effective against sophisticated filtering systems like TSPU
(Russia), GFW (China), and similar DPI infrastructure.

Key design goals:

- **Resilience** -- no single point of failure; if one strategy is blocked,
  the client seamlessly switches to another.
- **Stealth** -- traffic patterns are morphed to resemble legitimate services
  (video streaming, CDN traffic, HTTPS browsing).
- **Performance** -- multiplexed connections via smux, QUIC transport, and
  adaptive RTT masking minimize overhead.

---

## Features

- **20+ DPI bypass strategies** with automatic selection and mid-session fallback
- **QUIC and TLS transports** with Salamander padding and SNI fragmentation
- **REALITY protocol** -- impersonates legitimate websites with near-perfect TLS fingerprints
- **HTTP/2 steganography** -- hides tunnel data inside real HTTP/2 frames
- **Traffic morphing** -- statistically matches traffic patterns of popular services
- **Geneva engine** -- country-specific packet manipulation rules (Russia, China, Iran, Turkey)
- **Multiplexed connections** via smux for efficient stream management
- **TUN mode** for full system traffic tunneling
- **SOCKS5 and HTTP proxy** modes
- **Port hopping** with random, sequential, and Fibonacci strategies
- **IPv6 transport** with dual-stack support and automatic fallback
- **Encrypted Client Hello (ECH)** to hide SNI from DPI
- **Post-quantum cryptography** (ML-KEM-768 + ML-DSA-65)
- **Multi-hop routing** through chained servers
- **Prometheus-compatible metrics** endpoint
- **Android integration** via JNI (c-shared build mode)
- **Docker support** with multi-stage builds
- **Client management** with Redis backend and REST API
- **QR code generation** for mobile client provisioning

---

## How TiredVPN Compares

| Feature | TiredVPN | Xray/VLESS | sing-box | Outline |
|---------|----------|------------|----------|---------|
| Bypass strategies | 20+ | 3–5 | 5–8 | 1–2 |
| Adaptive fallback | ✅ Mid-session | ❌ | Partial | ❌ |
| TSPU research | Monthly reports | ❌ | ❌ | ❌ |
| Post-quantum crypto | ✅ ML-KEM-768 | ❌ | ❌ | ❌ |
| Geneva engine | ✅ | ❌ | ❌ | ❌ |
| RTT masking | ✅ | ❌ | ❌ | ❌ |
| ICMP fallback | ✅ | ❌ | ❌ | ❌ |
| Traffic morphing | ✅ | ❌ | ❌ | ❌ |
| Android app | ✅ Native | Third-party | Third-party | ✅ |
| License | AGPL-3.0 | MPL-2.0 | GPL-3.0 | Apache-2.0 |

---

## Quick Start

### Generate a shared secret

```bash
openssl rand -hex 32
```

### Server

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <your-secret>
```

The server listens on both TCP (TLS) and UDP (QUIC) by default. It serves a
fake website to unauthenticated visitors, making it indistinguishable from a
normal HTTPS server.

### Client (SOCKS5 proxy)

```bash
tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -listen 127.0.0.1:1080
```

This starts a local SOCKS5 proxy on port 1080. Point your browser or
applications to `socks5://127.0.0.1:1080`.

### Client (full VPN / TUN mode)

```bash
sudo tiredvpn client \
  -server your-server.com:443 \
  -secret <your-secret> \
  -tun \
  -tun-routes 0.0.0.0/0
```

This creates a TUN interface and routes all traffic through the VPN.

---

## Building from Source

### Requirements

- Go 1.26 or later
- Linux, macOS, or Windows (TUN mode requires Linux)

### Build

```bash
git clone https://github.com/tiredvpn/tiredvpn.git
cd tiredvpn
make build
```

Or directly with Go:

```bash
go build -o tiredvpn ./cmd/tiredvpn/
```

### Cross-compile for Linux (amd64)

```bash
make build-linux
```

### Cross-compile for Android (arm64)

```bash
make build-android
```

### Run tests

```bash
make test
```

---

## Configuration

TiredVPN is configured entirely via CLI flags. Run `tiredvpn server -help` or
`tiredvpn client -help` for the full list.

### Server flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:443` | IPv4 listen address |
| `-listen-v6` | `[::]:995` | IPv6 listen address |
| `-cert` | `server.crt` | TLS certificate file |
| `-key` | `server.key` | TLS private key file |
| `-secret` | | Shared secret (single-client mode) |
| `-redis` | | Redis address for multi-client mode |
| `-api-addr` | `127.0.0.1:8080` | REST API for client management |
| `-ip-pool` | | CIDR for TUN client IP assignment |
| `-port-range` | | Multi-port listening (e.g. `47000-47100`) |
| `-no-quic` | `false` | Disable QUIC/UDP listener |
| `-upstream` | | Upstream server for multi-hop |
| `-fake-root` | `./www` | Directory served to unauthenticated visitors |
| `-debug` | `false` | Verbose logging |

### Client flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | | Remote server address (required) |
| `-secret` | | Shared secret (required) |
| `-listen` | `127.0.0.1:1080` | Local SOCKS5/HTTP proxy address |
| `-tun` | `false` | Enable TUN mode (full VPN) |
| `-tun-routes` | | Routes to tunnel (e.g. `0.0.0.0/0`) |
| `-quic` | `false` | Enable QUIC transport |
| `-strategy` | | Force a specific strategy |
| `-port-hop` | `false` | Enable port hopping |
| `-ech` | `false` | Enable Encrypted Client Hello |
| `-pq` | `false` | Enable post-quantum crypto |
| `-rtt-masking` | `false` | Hide proxy timing signature |
| `-prefer-ipv6` | `true` | Prefer IPv6 transport |
| `-fallback` | `true` | Mid-session strategy fallback |
| `-benchmark` | `false` | Run strategy latency benchmark |

### Client management

```bash
# Add a client (multi-client mode with Redis)
tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443

# List clients
tiredvpn admin list -api http://127.0.0.1:8080

# Delete a client
tiredvpn admin delete -api http://127.0.0.1:8080 -id <client-id>

# Generate QR code for mobile app
tiredvpn admin qr -server vpn.example.com:443 -secret <secret>
```

---

## Docker

Pre-built images are available on Docker Hub. Platforms: `linux/amd64`, `linux/arm64`.

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `1.0.0` | Pinned version |
| `edge` | Latest main branch build |

### Run the server

```bash
docker run -d \
  --name tiredvpn-server \
  -p 443:443/tcp \
  -p 443:443/udp \
  -v /path/to/certs:/certs:ro \
  tiredvpn/tiredvpn:latest \
  server -listen :443 \
  -cert /certs/server.crt \
  -key /certs/server.key \
  -secret <your-secret>
```

### Docker Compose

```bash
curl -O https://raw.githubusercontent.com/tiredvpn/tiredvpn/main/docker-compose.yml
TIREDVPN_SECRET=<your-secret> docker compose up -d
```

Or with a custom `docker-compose.yml`:

```yaml
version: "3.8"

services:
  tiredvpn-server:
    image: tiredvpn/tiredvpn:latest
    ports:
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./certs:/certs:ro
    command:
      - "server"
      - "-listen"
      - ":443"
      - "-cert"
      - "/certs/server.crt"
      - "-key"
      - "/certs/server.key"
      - "-secret"
      - "${TIREDVPN_SECRET}"
      - "-redis"
      - "redis:6379"
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### Build locally

```bash
docker build -t tiredvpn .
```

---

## Strategies

TiredVPN includes an adaptive strategy engine that automatically selects the
best transport. Each strategy targets a different aspect of DPI evasion.

| ID | Name | Description |
|----|------|-------------|
| `quic_salamander` | QUIC Salamander | QUIC over UDP with Salamander padding (default, hardest to fingerprint) |
| `quic` | QUIC Tunnel | QUIC transport with version spoofing (draft-29 to bypass TSPU) |
| `reality` | REALITY Protocol | Impersonates legitimate websites with authentic TLS fingerprints |
| `http2_stego` | HTTP/2 Steganography | Hides data inside HTTP/2 frames with NaiveProxy-style padding |
| `websocket_padded` | WebSocket Salamander | WebSocket transport with Salamander obfuscation padding |
| `http_polling` | HTTP Polling | Short-lived HTTP/1.1 requests (meek-style), evades long-connection detection |
| `morph_*` | Traffic Morphing | Reshapes traffic to match video streaming profiles (Yandex, VK) |
| `confusion_*` | Protocol Confusion | Makes packets appear as DNS/HTTP/SSH/SMTP over TLS |
| `geneva_*` | Geneva Engine | Country-specific packet manipulation (Russia TSPU, China GFW, Iran, Turkey) |
| `antiprobe` | Anti-Probe | Server masquerades as normal website; reveals tunnel only to authenticated clients |
| `state_exhaustion` | State Exhaustion | Floods DPI state table with decoys to trigger fail-open mode |
| `mesh_relay` | Mesh Relay | Routes through relay nodes in regions with lighter filtering |
| `icmp_tunnel` | ICMP Tunnel | Backup tunnel over ICMP Echo (stealth mode, requires CAP_NET_RAW) |

The strategy engine supports:

- **Automatic probing** -- tests all available strategies and ranks by latency
- **Circuit breakers** -- disables failing strategies after configurable threshold
- **Mid-session fallback** -- switches strategy without dropping the connection
- **Periodic re-probing** -- re-evaluates blocked strategies on a timer
- **Benchmarking** -- `tiredvpn client -benchmark` to test all strategies

---

## Architecture

```
cmd/tiredvpn/          CLI entrypoint (server, client, admin)
internal/
  server/              Server-side connection handling, TLS/QUIC listeners
  client/              Client-side proxy, TUN, strategy orchestration
  strategy/            DPI bypass strategies and adaptive engine
  tun/                 TUN device management
  mux/                 smux multiplexer integration
  tunnel/              Tunnel abstractions
  proxy/               SOCKS5 and HTTP proxy
  tls/                 TLS utilities and uTLS fingerprinting
  evasion/             Low-level evasion primitives
  geneva/              Geneva packet manipulation engine
  porthopping/         Port hopping logic
  multiport/           Multi-port listener
  pool/                IP address pool for TUN clients
  metrics/             Prometheus metrics collector
  padding/             Traffic padding utilities
  protect/             Android VpnService socket protection
  control/             Android control socket protocol
  config/              Configuration types
  log/                 Structured logging
  benchmark/           Strategy benchmarking
  ktls/                Kernel TLS offload
```

---

## Documentation

Full documentation is available in the [docs/](docs/) directory:

- [Getting Started](docs/getting-started.md)
- [Server Reference](docs/server.md)
- [Client Reference](docs/client.md)
- [DPI Bypass Strategies](docs/strategies.md)
- [Deployment Guide](docs/deployment.md)
- [Security Model](docs/security.md)
- [Monitoring](docs/monitoring.md)

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on submitting patches, reporting issues, and the development
workflow.

Before submitting a pull request:

1. Run `make test` and ensure all tests pass
2. Run `make lint` if you have golangci-lint installed
3. Keep commits focused and well-described

---

## Community

- [Telegram Channel](https://t.me/tiredvpn) — announcements, TSPU reports, how-to guides
- [Telegram Chat](https://t.me/tiredvpn_chat) — questions and discussion
- [GitHub Discussions](https://github.com/tiredvpn/tiredvpn/discussions) — feature ideas, Q&A

---

## License

TiredVPN is licensed under the [GNU Affero General Public License v3.0](LICENSE).

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tiredvpn/tiredvpn&type=Date)](https://star-history.com/#tiredvpn/tiredvpn&Date)
