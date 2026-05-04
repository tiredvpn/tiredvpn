# Server Reference

Complete reference for `tiredvpn server`.

## Usage

```
tiredvpn server [options]
```

## Modes

### Single-client mode

One shared secret authenticates all connections. Simplest setup.

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <64-char-hex>
```

### Multi-client mode (Redis)

Each client has its own secret and optional rate limits. Requires Redis.

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080
```

Use `tiredvpn admin` to add/remove clients. See [admin.md](admin.md).

## Flag Reference

### CORE OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:443` | IPv4 listen address (TCP + QUIC UDP) |
| `-listen-v6` | `[::]:995` | IPv6 listen address |
| `-cert` | `server.crt` | TLS certificate file path |
| `-key` | `server.key` | TLS private key file path |
| `-secret` | | Shared secret for single-client mode (hex string from `openssl rand -hex 32`) |
| `-debug` | `false` | Enable verbose debug logging |

### IPv6 OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-enable-v6` | `true` | Enable IPv6 listener |
| `-dual-stack` | `true` | Listen on both IPv4 and IPv6 simultaneously |

Dual-stack lets clients choose the transport independently. Disable with `-dual-stack=false` if you only want IPv4.

### MULTI-CLIENT OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-redis` | | Redis address (e.g., `localhost:6379`). Enables multi-client mode. |
| `-api-addr` | `127.0.0.1:8080` | HTTP API for client management (only used with Redis) |
| `-ip-pool` | | CIDR block for TUN client IP assignment (e.g., `10.8.0.0/24`) |
| `-ip-pool-lease` | `24h` | Duration of IP lease per client |

The `-ip-pool` flag is required when clients connect in TUN mode (`tiredvpn client -tun`). The server assigns each client a unique IP from this pool.

### PORT HOPPING OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-port-range` | | Port or range to listen on (e.g., `995` or `47000-47100`) |
| `-port-range-max` | `50` | Maximum number of ports when using a range |
| `-port-hop-interval` | `1m` | Recommended hop interval advertised to clients |
| `-port-hop-strategy` | `random` | Hop strategy hint: `random`, `sequential`, `fibonacci` |
| `-port-hop-seed` | | Seed for deterministic hopping (must match client) |

Port hopping opens multiple listeners simultaneously. Clients rotate through ports based on the configured strategy. The server and client must use the same seed for deterministic strategies.

### QUIC OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-no-quic` | `false` | Disable the QUIC/UDP listener |
| `-quic-listen` | same as `-listen` | Override QUIC listen address (default: same address as `-listen`, UDP) |
| `-quic-sni-reassembly` | `false` | Enable SNI fragment reassembly (required when clients use `-quic-sni-frag`) |

### MULTI-HOP OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-upstream` | | Upstream TiredVPN server address (e.g., `exit-node.com:443`) |
| `-upstream-secret` | | Secret for authenticating to the upstream server |

Multi-hop chains two servers: the client connects to this server, which relays traffic through the upstream. Useful for adding an extra hop in a different jurisdiction.

```
Client → Server A (relay) → Server B (upstream/exit) → Internet
```

### ADVANCED OPTIONS

| Flag | Default | Description |
|------|---------|-------------|
| `-fake-root` | `./www` | Directory served as a fake website to unauthenticated visitors |
| `-tun-ip` | `10.8.0.1` | TUN interface IP address on the server side |
| `-tun-name` | `tiredvpn0` | TUN interface name |
| `-pprof` | | Enable pprof profiling endpoint (e.g., `:6060`) |
| `-version` | | Print version and exit |

The fake website (`-fake-root`) is what any DPI probe or direct browser sees when connecting without a valid auth token. Put static HTML files there to mimic a real web service.

## Configuration via TOML (preferred)

Since v1.1.0 the server accepts `--config <path>` to load all options from a
TOML file. Any CLI flag passed alongside overrides the file value
(precedence: CLI > TOML > defaults), so existing systemd units keep working.

```bash
tiredvpn server --config /etc/tiredvpn/server.toml
```

A copy-paste-ready template lives in [`configs/server.example.toml`](../configs/server.example.toml).

Minimal example:

```toml
[listen]
address = "0.0.0.0"
port    = 443

[strategy]
mode = "reality"

[tls]
cert_file = "/etc/tiredvpn/server.crt"
key_file  = "/etc/tiredvpn/server.key"

[auth]
mode         = "token"
tokens_file  = "/etc/tiredvpn/secrets.txt"

[logging]
level = "info"
```

Most CLI-only flags (Redis multi-tenancy, port-hopping range, monitoring
endpoints, post-quantum) are not yet mapped to TOML and stay command-line
only — see the
[migration guide](../internal/config/toml/MIGRATION.md) for the field-by-field
table and roadmap.

## Traffic Shaper (server side)

Server-side shaping is **opt-in**. By default the server is shaper-agnostic:
each `MorphedConn` runs `NoopShaper` so server-to-client throughput is native.
Enable `[shaper]` only when your threat model requires the server to also
emit a specific statistical signature on its egress traffic.

```toml
[shaper]
preset = "chrome_browsing"
```

Available presets and trade-offs are identical to the client side —
see [client.md → Traffic Shaper](client.md#traffic-shaper). The
`bittorrent_idle` preset is rejected in the data plane (≈7 s median
inter-arrival is incompatible with tunnelling user payload).

## Configuration Examples

### Minimal single-client

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret $(openssl rand -hex 32)
```

### Dual-stack (IPv4 + IPv6)

```bash
tiredvpn server \
  -listen :443 \
  -listen-v6 [::]:995 \
  -dual-stack \
  -cert server.crt \
  -key server.key \
  -secret <secret>
```

### Multi-client with Redis and TUN IP pool

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080 \
  -ip-pool 10.8.0.0/24
```

### Port hopping (50 ports, random strategy)

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret> \
  -port-range 47000-47100 \
  -port-hop-interval 1m \
  -port-hop-strategy random
```

Clients must enable `-port-hop` with matching range parameters.

### Multi-hop relay

```bash
# This server relays through exit-node.example.com
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <relay-secret> \
  -upstream exit-node.example.com:443 \
  -upstream-secret <upstream-secret>
```

### Production (all features)

```bash
tiredvpn server \
  -listen :443 \
  -listen-v6 [::]:995 \
  -dual-stack \
  -cert /etc/tiredvpn/server.crt \
  -key /etc/tiredvpn/server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080 \
  -ip-pool 10.8.0.0/16 \
  -ip-pool-lease 24h \
  -port-range 47000-47100 \
  -fake-root /var/www/tiredvpn \
  -quic-sni-reassembly
```

## Fake website

Create a convincing fake website to deflect DPI probes:

```bash
mkdir -p /var/www/tiredvpn
cat > /var/www/tiredvpn/index.html << 'EOF'
<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>Under Construction</h1></body>
</html>
EOF

tiredvpn server -fake-root /var/www/tiredvpn ...
```

Any HTTP request without a valid auth token receives this page with a `200 OK` response.

## API Endpoints

When running in multi-client mode, the REST API is available at `-api-addr`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/clients` | List all clients |
| `POST` | `/clients` | Create a new client |
| `GET` | `/clients/{id}` | Get client details |
| `PUT` | `/clients/{id}` | Update client |
| `DELETE` | `/clients/{id}` | Delete client |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/health` | Server health status |

See [admin.md](admin.md) for usage examples and [monitoring.md](monitoring.md) for metrics details.
