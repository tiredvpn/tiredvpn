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

- **Resilience** - no single point of failure; if one strategy is blocked,
  the client seamlessly switches to another.
- **Stealth** - traffic patterns are morphed to resemble legitimate services
  (video streaming, CDN traffic, HTTPS browsing).
- **Performance** - multiplexed connections via smux, QUIC transport, and
  adaptive RTT masking minimize overhead.

---

## Features

- **20+ DPI bypass strategies** with automatic selection and mid-session fallback
- **QUIC and TLS transports** with Salamander padding and SNI fragmentation
- **REALITY protocol** - impersonates legitimate websites with near-perfect TLS fingerprints
- **HTTP/2 steganography** - hides tunnel data inside real HTTP/2 frames
- **Traffic morphing** - statistically matches traffic patterns of popular services
- **Geneva engine** - country-specific packet manipulation rules (Russia, China, Iran, Turkey)
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
| TSPU research | [Daily reports](https://github.com/tiredvpn/tiredvpn-measurements) | ❌ | ❌ | ❌ |
| Post-quantum crypto | ✅ ML-KEM-768 | ❌ | ❌ | ❌ |
| Geneva engine | ✅ | ❌ | ❌ | ❌ |
| RTT masking | ✅ | ❌ | ❌ | ❌ |
| ICMP fallback | ✅ | ❌ | ❌ | ❌ |
| Traffic morphing | ✅ | ❌ | ❌ | ❌ |
| Android app | ✅ Native | Third-party | Third-party | ✅ |
| License | AGPL-3.0 | MPL-2.0 | GPL-3.0 | Apache-2.0 |

---

## Quick Start

### Install

#### One-liner (recommended)

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/install.sh | sudo bash -s -- --port 443
```

Installs the server, generates a secret and TLS cert, starts the service, and
prints the connection string plus a QR code for the mobile app. Pick a different
port with `--port N` (default 443).

#### Debian/Ubuntu (apt)

```bash
curl -fsSL https://tiredvpn.github.io/tiredvpn/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/tiredvpn-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/tiredvpn-archive-keyring.gpg] https://tiredvpn.github.io/tiredvpn/apt stable main" | sudo tee /etc/apt/sources.list.d/tiredvpn.list
sudo apt update && sudo apt install tiredvpn
sudo tiredvpn-init        # generates secret/cert, prints keys, starts the service
```

#### Fedora/RHEL (dnf)

```bash
sudo tee /etc/yum.repos.d/tiredvpn.repo >/dev/null <<'EOF'
[tiredvpn]
name=TiredVPN
baseurl=https://tiredvpn.github.io/tiredvpn/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://tiredvpn.github.io/tiredvpn/gpg.key
EOF
sudo dnf install tiredvpn && sudo tiredvpn-init
```

The apt and dnf packages install the service in a **disabled** state - they
ship the binary but leave it stopped. Run `sudo tiredvpn-init` to finish setup:
it generates the secret and cert, prints the access keys, and starts the
service. The one-liner and `install.sh` already do this for you.

By default the service comes up in **TUN mode** (`TIREDVPN_IP_POOL=10.8.0.0/24`)
and sets `ip_forward` + NAT for the pool on each start, so the Android app (which
always uses native TUN) works out of the box - no manual forwarding. For
proxy-only, use `install.sh --proxy-only` or `tiredvpn-init --proxy-only`. Pick a
different pool with `tiredvpn-init --ip-pool <CIDR>`. Details:
[Server firewall and forwarding](#server-firewall-and-forwarding-required-for-tun-mode).

#### Manual binary download

For other distros or hosts without systemd, download the binary directly:

```bash
curl -LO https://github.com/tiredvpn/tiredvpn/releases/latest/download/tiredvpn-linux-amd64.tar.gz
tar xzf tiredvpn-linux-amd64.tar.gz
sudo mv tiredvpn-linux-amd64 /usr/local/bin/tiredvpn
```

Available platforms: `linux-amd64`, `linux-arm64`. Other installation
methods are described in the [Docker](#docker) and
[Building from Source](#building-from-source) sections below.

Kubernetes via Helm (server and/or client from a single release):

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn --version 0.1.0 \
  -f my-values.yaml
```

See [deploy/helm/tiredvpn/README.md](deploy/helm/tiredvpn/README.md) for values, examples, and TLS/auth/Redis/HPA options.

### Generate a shared secret

> The steps below (secret, certs, server flags) are for manual or advanced
> setups only. The one-liner and the apt/dnf packages handle all of this for
> you via `tiredvpn-init` - skip ahead to the app sections if you used one of
> those.

```bash
openssl rand -hex 32
```

### Generate TLS certificates

For testing, create a self-signed certificate:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 365 -nodes -keyout server.key -out server.crt \
  -subj "/CN=your-server.com"
```

For production, use [Let's Encrypt](https://letsencrypt.org/) with certbot:

```bash
sudo certbot certonly --standalone -d your-server.com
# Certificates will be at:
#   /etc/letsencrypt/live/your-server.com/fullchain.pem
#   /etc/letsencrypt/live/your-server.com/privkey.pem
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

### Server firewall and forwarding (required for TUN mode)

> **Installed via `install.sh`, the one-liner, or apt/dnf?** Nothing to do here.
> Those paths set up TUN by default: the env file gets
> `TIREDVPN_IP_POOL=10.8.0.0/24`, and on every service start
> `ExecStartPre=/usr/bin/tiredvpn-nat` flips `net.ipv4.ip_forward=1` and installs
> the `MASQUERADE` + `FORWARD` rules for the pool (idempotent). This is what lets
> the Android app - which always uses native TUN - connect to a fresh install
> with no manual steps. To opt out and run proxy-only, use
> `install.sh --proxy-only` / `tiredvpn-init --proxy-only`, or set
> `TIREDVPN_IP_POOL=` (empty) in `/etc/tiredvpn/env` and restart. Custom CIDR:
> `tiredvpn-init --ip-pool <CIDR>`.
>
> The manual steps below are only for running the binary directly (from source or
> a raw download) without the package or systemd unit.

**If you run the binary yourself in TUN mode (`-tun` / `-ip-pool`), you must
enable IP forwarding and NAT on the server host yourself.** The binary
deliberately does not modify your firewall or routing. Without this, a TUN
client connects and the server logs `TUN mode established`, but no traffic flows
- the client's packets reach the server's TUN interface and have nowhere to go.
(SOCKS5 proxy mode is unaffected: the server process egresses that traffic
itself.)

```bash
# 1) Enable IP forwarding (persist it too)
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# 2) NAT the client pool out your uplink interface.
#    Find the uplink with: ip route get 1.1.1.1   (the "dev <iface>" part)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o <wan-iface> -j MASQUERADE

# 3) Only if your FORWARD policy is DROP (check: iptables -S FORWARD | head -1)
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -d 10.8.0.0/24 -j ACCEPT
```

Replace `10.8.0.0/24` with your `-ip-pool` CIDR and `<wan-iface>` with your real
uplink (e.g. `eth0`, `enp1s0`). For IPv6 pools, mirror the rules with `ip6tables`
and `net.ipv6.conf.all.forwarding=1`. Use a firewall manager (nftables, ufw,
firewalld) if you prefer - the requirement is the same: forward and NAT the pool.

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
| `-tun-mtu` | `1280` | TUN interface MTU (1280-9000) |
| `-port-range` | | Multi-port listening (e.g. `47000-47100`) |
| `-no-quic` | `false` | Disable QUIC/UDP listener |
| `-upstream` | | Upstream server for multi-hop |
| `-fake-root` | `./www` | Directory served to unauthenticated visitors |
| `-enable-icmp` | `false` | Enable ICMP tunnel listener (requires CAP_NET_RAW) |
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
| `1.3.3` | Pinned version |
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

### TUN mode in containers

The default image is a scratch proxy build with no `iptables`, so server-side
TUN (`-ip-pool`) does not work in it. For full TUN tunnelling use the `tun`
build target (`tiredvpn:tun`), which needs `/dev/net/tun`, `NET_ADMIN`, and a
writable `net.ipv4.ip_forward`; its entrypoint sets up NAT for you. The same
applies to Helm via `server.tun.enabled`. Full docker run / compose / Helm
recipes are in
[docs/deployment.md → TUN mode in containers](docs/deployment.md#tun-mode-in-containers).

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
| `ssh_camouflage` | SSH Camouflage | Tunnel under SSH traffic (priority 28, requires server support) |
| `imap_camouflage` | IMAP Camouflage | Tunnel under IMAP mail protocol (priority 29, requires server support) |

The strategy engine supports:

- **Automatic probing** - tests all available strategies and ranks by latency
- **Circuit breakers** - disables failing strategies after configurable threshold
- **Mid-session fallback** - switches strategy without dropping the connection
- **Periodic re-probing** - re-evaluates blocked strategies on a timer
- **Benchmarking** - `tiredvpn client -benchmark` to test all strategies

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

- [GitHub Discussions](https://github.com/tiredvpn/tiredvpn/discussions) — feature ideas, Q&A

---

## License

TiredVPN is licensed under the [GNU Affero General Public License v3.0](LICENSE).

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tiredvpn/tiredvpn&type=Date)](https://star-history.com/#tiredvpn/tiredvpn&Date)
