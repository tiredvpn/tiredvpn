# TiredVPN

> A DPI-resistant VPN designed to work in heavily censored networks.

[![CI](https://github.com/tiredvpn/tiredvpn/actions/workflows/ci.yml/badge.svg)](https://github.com/tiredvpn/tiredvpn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tiredvpn/tiredvpn)](https://github.com/tiredvpn/tiredvpn/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/tiredvpn/tiredvpn)](https://hub.docker.com/r/tiredvpn/tiredvpn)
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
The same applies one level down: a client can be given a list of servers, and
the address family and the server are both re-decided at runtime rather than
settled once at startup. This targets filtering systems like TSPU (Russia),
GFW (China), and similar DPI infrastructure.

Key design goals:

- **Resilience** - no single point of failure. A blocked strategy, a dead IPv6
  path, or an unreachable server each get replaced without a restart.
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
- **Server pool** - a list of endpoints in TOML with `priority`, `latency`, or
  `weighted` selection, and per-candidate parking with exponential cooldown
- **Runtime transport fallback** - the address family is re-decided during the
  session, not fixed at startup
- **IPv6 inside the tunnel** (dual-stack), on by default, with outbound IPv6
  blocked when the exit cannot carry it so it does not leak around the VPN
- **Port hopping** with random, sequential, and Fibonacci strategies
- **Encrypted Client Hello (ECH)** to hide SNI from DPI
- **Post-quantum cryptography** (ML-KEM-768 + ML-DSA-65)
- **Multi-hop routing** through chained servers
- **TOML configuration** with CLI overrides (`-config`)
- **Native packages** - `.deb`/`.rpm`, signed apt/yum repositories, one-line
  installer, and a systemd unit that brings up forwarding and NAT itself
- **Prometheus-compatible metrics** endpoint
- **Android integration** via JNI (c-shared build mode)
- **Docker and Helm** - multi-arch images and a chart on ghcr.io
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
base=https://github.com/tiredvpn/tiredvpn/releases/latest/download
curl -LO $base/tiredvpn-linux-amd64.tar.gz
curl -LO $base/checksums.txt
grep tiredvpn-linux-amd64.tar.gz checksums.txt | sha256sum -c -
tar xzf tiredvpn-linux-amd64.tar.gz
sudo mv tiredvpn-linux-amd64 /usr/local/bin/tiredvpn
```

Available platforms: `linux-amd64`, `linux-arm64`. This gives you the binary
only - no systemd unit and no `tiredvpn-init`; use `install.sh --method binary`
if you want those too. Other installation methods are described in the
[Docker](#docker) and [Building from Source](#building-from-source) sections
below.

Kubernetes via Helm (server and/or client from a single release):

```bash
helm install my-tiredvpn oci://ghcr.io/tiredvpn/charts/tiredvpn --version 0.3.0 \
  -f my-values.yaml
```

The chart is versioned separately from the binary: chart `0.3.2` ships
`appVersion` 1.5.1. Each tagged release patch-bumps the chart and pushes it to
the OCI registry.

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

**Automatic, for every way of running the server** - package, Docker, or the
raw binary. Whenever `-ip-pool` is set (the packaged unit sets it by default:
`TIREDVPN_IP_POOL=10.8.0.0/24` in `/etc/tiredvpn/env`), the server flips
`net.ipv4.ip_forward=1` and installs `MASQUERADE` + `FORWARD` nftables rules
for the pool on the WAN interface (autodetected via the route to `1.1.1.1`;
override with the `TIREDVPN_WAN_IFACE` env var) directly over netlink on
start - no `iptables`/`ip` binaries, no wrapper script, nothing to install.
This is what lets the Android app - which always uses native TUN - connect to
a fresh install with no manual steps. Failure is non-fatal: a host without
`CAP_NET_ADMIN` logs a warning and comes up proxy-degraded rather than
refusing to start.

To opt out and run proxy-only: `install.sh --proxy-only` /
`tiredvpn-init --proxy-only`, or set `TIREDVPN_IP_POOL=` (empty) in
`/etc/tiredvpn/env` and restart. Custom CIDR: `tiredvpn-init --ip-pool <CIDR>`.

**The automatic setup is IPv4-only.** For an IPv6 pool, or if you'd rather
manage NAT yourself (a shared box with its own firewall policy, etc.), the
automatic MASQUERADE/FORWARD install only ever touches the `-ip-pool` CIDR, so
your own rules just coexist with it:

```bash
# Find the uplink with: ip route get 1.1.1.1   (the "dev <iface>" part)
ip6tables -t nat -A POSTROUTING -s <ipv6-pool> -o <wan-iface> -j MASQUERADE
ip6tables -A FORWARD -s <ipv6-pool> -j ACCEPT
ip6tables -A FORWARD -d <ipv6-pool> -j ACCEPT
sysctl -w net.ipv6.conf.all.forwarding=1
```

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

Since 1.5.0 `-tun-ipv6` defaults to `dual`: IPv6 goes through the tunnel when
the exit was started with `-ip-pool-v6`, and is rejected outright when it was
not, so applications cannot reach the internet over a native IPv6 default route
while the VPN is up. `-tun-ipv6 off` restores the pre-1.5.0 behaviour, which is
what a split tunnel usually wants - `dual` sends *all* IPv6 into the tunnel,
including destinations you deliberately routed around it on IPv4. The blocking
half is Linux-only; on macOS it warns instead.

If the host carries IPv6 of its own - a 6in4 tunnel, another VPN, a routed
prefix - name it with `-tun-ipv6-allow he6,2001:db8::/32` (interface names,
prefixes, or both) and the block leaves it alone.

---

## Configuration

TiredVPN takes configuration from CLI flags, from a TOML file (`-config`), or
from both. Precedence is **CLI flag > TOML > default**, and a flag counts as
set only if it was passed explicitly - leaving it at its default value never
overwrites a TOML field.

```bash
tiredvpn client -config /etc/tiredvpn/client.toml
tiredvpn server -config /etc/tiredvpn/server.toml
```

Annotated examples: [`configs/client.example.toml`](configs/client.example.toml)
and [`configs/server.example.toml`](configs/server.example.toml). Unknown keys
are rejected, so a typo fails at startup instead of being ignored.

TOML does not yet cover the whole flag surface. On the client it carries the
server list, the selection policy, `strategy.mode`, `tls.fingerprint`, the
shaper and the log level; on the server, the listen address, the certificate
and key, and the log level. Everything else - `-secret`, the `-tun-*` flags,
the evasion knobs - is still flags only. The full mapping and the deprecation
plan are in
[`internal/config/toml/MIGRATION.md`](internal/config/toml/MIGRATION.md).

Run `tiredvpn server -help` or `tiredvpn client -help` for the full flag list.

### Server flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | | Path to a TOML config; CLI flags override it |
| `-listen` | `:443` | IPv4 listen address |
| `-listen-v6` | | IPv6 listen address (default: `[::]` on the `-listen` port) |
| `-dual-stack` | `true` | Listen on both IPv4 and IPv6 |
| `-cert` | `server.crt` | TLS certificate file |
| `-key` | `server.key` | TLS private key file |
| `-secret` | | Shared secret (single-client mode) |
| `-redis` | | Redis address for multi-client mode |
| `-redis-db` | `0` | Redis logical database, 0-15 (`TIREDVPN_REDIS_DB`) |
| `-redis-prefix` | `tiredvpn:` | Redis key namespace (`TIREDVPN_REDIS_PREFIX`) |
| `-api-addr` | `127.0.0.1:8080` | REST API for client management |
| `-api-token` | | Bearer token for the management API (`TIREDVPN_API_TOKEN`) |
| `-ip-pool` | | CIDR for TUN client IP assignment |
| `-ip-pool-v6` | | IPv6 ULA prefix for dual-stack TUN clients |
| `-tun-mtu` | `1280` | TUN interface MTU (1280-9000) |
| `-port-range` | | Multi-port listening (e.g. `47000-47100`) |
| `-no-quic` | `false` | Disable QUIC/UDP listener |
| `-upstream` | | Upstream server for multi-hop |
| `-fake-root` | `./www` | Directory served to unauthenticated visitors |
| `-enable-icmp` | `false` | Enable ICMP tunnel listener (requires CAP_NET_RAW) |
| `-reality-b1` | `false` | Accept the REALITY B1 transport; needs `-reality-private-key` |
| `-reality-private-key` | | Static X25519 key, base64 (`TIREDVPN_REALITY_PRIVATE_KEY`) |
| `-max-conns` | `0` | Cap on in-flight incoming connections (0 = 4096) |
| `-pprof` | | Serve pprof on this address (e.g. `:6060`) |
| `-debug` | `false` | Verbose logging |

Generate the B1 key pair with `tiredvpn reality-keygen`.

### Client flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | | Path to a TOML config; CLI flags override it |
| `-server` | | Remote server address (required unless the config lists servers) |
| `-server-v6` | | Same server over IPv6 (e.g. `[2001:db8::1]:995`) |
| `-server-policy` | | Order of the `[[servers]]` list: `priority`, `latency`, `weighted` (empty = `priority`) |
| `-secret` | | Shared secret (required) |
| `-listen` | `127.0.0.1:1080` | Local SOCKS5/HTTP proxy address |
| `-http-listen` | | Separate HTTP proxy address |
| `-tun` | `false` | Enable TUN mode (full VPN) |
| `-tun-routes` | | Routes to tunnel (e.g. `0.0.0.0/0`) |
| `-tun-ipv6` | `dual` | IPv6 while the tunnel is up: `dual`, `block`, `off` |
| `-tun-ipv6-allow` | | Exceptions to the IPv6 block: interface names and/or prefixes, comma-separated |
| `-tun-mtu` | `1280` | TUN MTU; with `-auto-mtu` this is the upper bound |
| `-auto-mtu` | `true` | Probe the real end-to-end MTU and apply `min(probed, -tun-mtu)` |
| `-quic` | `false` | Enable QUIC transport |
| `-strategy` | | Force a specific strategy (`-list` prints them) |
| `-seqovl-packet` | `false` | Packet-level TCP sequence overlap for `seqovl` (Linux + CAP_NET_ADMIN) |
| `-port-hop` | `false` | Enable port hopping |
| `-ech` | `false` | Enable Encrypted Client Hello |
| `-pq` | `false` | Enable post-quantum crypto |
| `-rtt-masking` | `false` | Hide proxy timing signature |
| `-shaper` | | Traffic shaper preset for the morph strategies |
| `-prefer-ipv6` | `true` | Prefer IPv6 transport |
| `-fallback-v4` | `true` | Fall back to IPv4 if IPv6 fails |
| `-fallback` | `true` | Mid-session strategy fallback |
| `-benchmark` | `false` | Run strategy latency benchmark |
| `-debug` | `false` | Verbose logging |

### Several servers

A list of servers is config-file only - there is no flag that takes more than
one address. `[server]` and `[[servers]]` are mutually exclusive (a lone
`[server]` *is* a one-element list), and passing `-server` collapses whatever
the file says to a single entry.

```toml
[[servers]]
name = "ams"
address = "203.0.113.10"
port = 443
address_v6 = "2001:db8::10"
weight = 100

[[servers]]
name = "fra"
address = "203.0.113.20"
port = 443
weight = 50

[selection]
policy = "priority"      # priority (list order) | latency | weighted
family = "prefer_v6"     # prefer_v6 | prefer_v4 | v6_only | v4_only
failure_threshold = 2    # failed connect cycles before a candidate is parked
cooldown = "1m"          # first cooldown; doubles per repeat, jittered
max_cooldown = "30m"
min_dwell = "5m"         # hold a fallback this long before going back
health_check = "off"     # off | active
```

A dial target is an (endpoint, family) pair, so moving from IPv6 to IPv4 and
moving between servers are the same operation. Background health checking is
off by default on purpose: polling every server on a timer is a periodic
fan-out pattern with nothing behind it. With it off, the client learns a server
is up by dialling it.

### Client management

```bash
# Add a client (multi-client mode with Redis); -name is required
tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443 -name alice

# List clients
tiredvpn admin list -api http://127.0.0.1:8080

# Delete a client
tiredvpn admin delete -api http://127.0.0.1:8080 -id <client-id>

# Generate QR code for mobile app
tiredvpn admin qr -server vpn.example.com:443 -secret <secret>
```

If the server runs with `-api-token`, pass the same value as `-api-token` to
the `add`, `list`, and `delete` subcommands (or set `TIREDVPN_API_TOKEN`).

---

## Docker

Pre-built images are available on Docker Hub. Platforms: `linux/amd64`, `linux/arm64`.

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `1.5.1` | Pinned version (one tag per release) |
| `edge` | Latest `main` branch build |

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

The default image handles server-side TUN (`-ip-pool`) out of the box - the
binary sets up NAT itself via netlink/nftables on start, no special build
needed. It just needs `/dev/net/tun`, `NET_ADMIN`, and a writable
`net.ipv4.ip_forward` from the container runtime. The same applies to Helm via
`server.tun.enabled`. Full docker run / compose / Helm recipes are in
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
make build          # -> ./tiredvpn
```

Or directly with Go (this skips the `-X main.version` ldflag, so
`tiredvpn -version` reports `dev`):

```bash
go build -o tiredvpn ./cmd/tiredvpn/
```

### Other targets

| Target | Output |
|--------|--------|
| `make build-linux` | `tiredvpn-linux-amd64` |
| `make build-android` | `libtiredvpn.so` (arm64 c-shared, needs CGo) |
| `make build-macos-cli` | `tiredvpn-macos-arm64`, `tiredvpn-macos-amd64` |
| `make build-macos-lib` | `build/macos/libtiredvpn.a` (universal; macOS host only) |

### Run tests

```bash
make test           # go test -race ./internal/...
make lint           # golangci-lint run ./...
```

---

## Strategies

TiredVPN includes an adaptive strategy engine that automatically selects the
best transport. Each strategy targets a different aspect of DPI evasion.
`tiredvpn client -list` prints the ones registered for your current flags, in
priority order; `-strategy <id>` pins one.

| ID | Name | Description |
|----|------|-------------|
| `reality` | REALITY Protocol | Impersonates legitimate websites with authentic TLS fingerprints (first in the default order) |
| `quic_salamander` | QUIC Salamander | QUIC over UDP with Salamander padding (opt-in: `-quic`) |
| `quic` | QUIC Tunnel | QUIC transport with version spoofing, draft-29 to bypass TSPU (opt-in: `-quic`) |
| `seqovl` | Seqovl (Sequence Overlap) | Prepends a secret-marked decoy TLS record before the REALITY ClientHello to desync stateful DPI reassembly (packet-level overlap on Linux via `-seqovl-packet`) |
| `http2_stego` | HTTP/2 Steganography | Hides data inside HTTP/2 frames with NaiveProxy-style padding |
| `websocket_padded` | WebSocket Salamander | WebSocket transport with Salamander obfuscation padding |
| `http_polling` | HTTP Polling | Short-lived HTTP/1.1 requests (meek-style), evades long-connection detection |
| `morph_*` | Traffic Morphing | Reshapes traffic to match video streaming profiles (Yandex, VK, Baidu, Aparat) |
| `confusion_*` | Protocol Confusion | Makes packets appear as DNS/HTTP/SSH/SMTP over TLS, plus a multi-layer variant |
| `geneva_*` | Geneva Engine | Country-specific packet manipulation. Registered by default: `geneva_russia`, `geneva_china`, `geneva_iran`. Turkey rules exist in the engine but are not registered as a strategy. |
| `antiprobe` | Anti-Probe | Server masquerades as normal website; reveals tunnel only to authenticated clients |
| `state_exhaustion` | State Exhaustion | Floods DPI state table with decoys to trigger fail-open mode |
| `mesh_relay` | Mesh Relay | Routes through relay nodes in regions with lighter filtering (opt-in, needs relay nodes configured) |
| `icmp_tunnel` | ICMP Tunnel | Backup tunnel over ICMP Echo (opt-in: `-icmp-tunnel`, requires CAP_NET_RAW and a server started with `-enable-icmp`) |
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
cmd/tiredvpn/          CLI entrypoint (server, client, admin, reality-keygen)
internal/
  server/              Server-side connection handling, TLS/QUIC listeners
  client/              Client-side proxy, TUN, strategy orchestration
  strategy/            DPI bypass strategies and adaptive engine
  endpoint/            Server pool: candidates, selection policy, parking
  tun/                 TUN device management, routes, IPv6 policy
  mux/                 smux multiplexer integration
  protocol/            Wire format and handshake versions
  tls/                 TLS utilities and uTLS fingerprinting
  evasion/             Low-level evasion primitives
  geneva/              Geneva packet manipulation engine
  detect/              Network and blocking detection
  porthopping/         Port hopping logic
  pool/                IP address pool for TUN clients
  shaper/              Behavioural traffic shaping (presets, distributions)
  metrics/             Prometheus metrics collector
  padding/             Traffic padding utilities
  protect/             Android VpnService socket protection
  control/             Android control socket protocol
  capabilities/        Runtime capability probing
  config/toml/         TOML schema, loader, and CLI-override resolver
  log/                 Structured logging
  benchmark/           Strategy benchmarking
  buildinfo/           Version and build metadata
  integration/         Cross-package integration tests
  ktls/                Kernel TLS offload
```

---

## Documentation

Full documentation is available in the [docs/](docs/) directory:

- [Getting Started](docs/getting-started.md)
- [Server Reference](docs/server.md)
- [Client Reference](docs/client.md)
- [Admin and Client Management](docs/admin.md)
- [DPI Bypass Strategies](docs/strategies.md)
- [Architecture](docs/architecture.md)
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
