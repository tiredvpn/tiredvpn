# Server Reference

Complete reference for `tiredvpn server` (v1.5.1).

## Usage

```
tiredvpn server [options]
```

Everything below is bound in `registerServerFlags` (`cmd/tiredvpn/main.go`) and
read by `server.Run` (`internal/server/server.go`).

## Modes

### Single-client mode

One shared secret authenticates every connection. No external dependency.

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <64-char-hex>
```

Without `-redis`, a secret is mandatory: the server exits with
`secret is required: set -secret flag or TIREDVPN_SECRET env variable`.

Clients that share one secret also share one identity. The IP pool cannot key a
lease on a shared secret, so two such clients cannot hold distinct tunnel
addresses; use multi-client mode when each user needs a stable IP.

### Multi-client mode (Redis)

Each client gets its own secret, optional connection cap and optional expiry.
Requires Redis.

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080 \
  -api-token "$(openssl rand -hex 32)"
```

Clients are managed through the REST API or `tiredvpn admin` - see
[admin.md](admin.md). The API server, the Prometheus endpoint and the stats
flush loop only start in this mode; `-api-addr` and `-api-token` do nothing
without `-redis`.

### Relay mode (multi-hop)

`-upstream` turns the instance into a relay: it terminates the client
connection and re-encapsulates the traffic towards another TiredVPN server.

```
Client -> Server A (-upstream) -> Server B (exit) -> Internet
```

A relay needs no `-ip-pool` and no TUN device; TUN packets are forwarded to the
exit. `-upstream-secret` is mandatory when `-upstream` is set.

## Flag Reference

### Core

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:443` | IPv4 TCP listen address. The socket is opened as `tcp4`; a bare `:port` is expanded to `0.0.0.0:port`. Also the default QUIC/UDP address. |
| `-cert` | `server.crt` | TLS certificate (PEM). Load failure aborts startup. |
| `-key` | `server.key` | TLS private key (PEM). |
| `-secret` | | Shared secret for single-client mode. Falls back to `TIREDVPN_SECRET`. |
| `-fake-root` | `./www` | Directory served to unauthenticated visitors. See [Fake website](#fake-website). |
| `-debug` | `false` | Verbose logging. |
| `-config` | | Path to a TOML config. See [Configuration via TOML](#configuration-via-toml). |
| `-pprof` | | Address for the `net/http/pprof` endpoint, e.g. `:6060`. |
| `-version` | `false` | Print version and exit. `tiredvpn -version` short-circuits before any other work. |

### IPv6 transport

| Flag | Default | Description |
|------|---------|-------------|
| `-listen-v6` | empty | IPv6 listen address. Empty means `[::]` on the `-listen` port. |
| `-enable-v6` | `true` | Start the IPv6 listener. Skipped when false, and when `-listen-v6` is empty and no address can be derived from `-listen` — the log says which. |
| `-dual-stack` | `true` | Accepted, but nothing reads it. The IPv6 listener is gated by `-enable-v6` alone; IPv4 always listens. |

An empty `-listen-v6` takes the port from `-listen` and widens the host to
`[::]`: `-listen :443` gives `[::]:443`, `-listen 1.2.3.4:994` gives `[::]:994`.
`-listen [::]:997` gives `[::]:997` — the IPv4 listener reads a wildcard host as
`0.0.0.0`, and the IPv6 socket is `V6ONLY`, so both sit on the port.

Two cases leave IPv6 off with a reason in the log: a `-listen` with no port or
an unparsable one, and a `-listen` naming a *concrete* IPv6 address such as
`[2001:db8::1]:443`. The second one stops the server outright, before the IPv6
listener is reached — the IPv4 listener cannot bind an IPv6 address. Give both
families explicitly (`-listen` plus `-listen-v6`) instead.

These control the *transport* the client dials. IPv6 **inside** the tunnel is
`-ip-pool-v6`.

### Multi-client (Redis)

| Flag | Default | Description |
|------|---------|-------------|
| `-redis` | | Redis address, e.g. `localhost:6379`. Non-empty enables multi-client mode. |
| `-redis-db` | `0` | Logical database, `0`-`15`. Falls back to `TIREDVPN_REDIS_DB`. Out-of-range aborts startup. |
| `-redis-prefix` | `tiredvpn:` | Key namespace. Falls back to `TIREDVPN_REDIS_PREFIX`. A trailing `:` is appended if missing; an empty value resolves to `tiredvpn:`. |
| `-api-addr` | `127.0.0.1:8080` | Management API address. Only used with `-redis`. |
| `-api-token` | | Bearer token required on every API endpoint. Falls back to `TIREDVPN_API_TOKEN`. Empty disables authentication. |

Keys written under the prefix: `<prefix>clients:<uuid>`,
`<prefix>secrets:<hash>`, `<prefix>stats:<uuid>`, `<prefix>version`, plus the
IP-pool lease keys. Keyspace-notification channels include both the database
index and the prefix, so two correctly separated instances never see each
other's events.

Running more than one server instance against the same Redis (an entry node
plus relays on one host, for example) requires giving each its own `-redis-db`
or `-redis-prefix`. Instances that share both also share the client registry,
the secret index and the IP-pool lease namespace, so they hand out the same
tunnel addresses and see each other's clients. The flags take precedence over
the env vars, which exist so a systemd `EnvironmentFile` can set them per unit.

The server also enables `notify-keyspace-events KEA` on the Redis instance at
startup, and polls the `<prefix>version` counter every 30 s as a fallback.

### TUN and IP pool

| Flag | Default | Description |
|------|---------|-------------|
| `-ip-pool` | | CIDR for client tunnel addresses, e.g. `10.8.0.0/24`. Enables the shared TUN device, the IP pool and the NAT bootstrap. |
| `-ip-pool-lease` | `24h` | Lease duration per client. `0` = permanent. |
| `-ip-pool-v6` | | ULA prefix for dual-stack clients, e.g. `fd00:10:8::/64`. Enables IPv6 inside the tunnel and NAT66. |
| `-tun-ip` | `10.8.0.1` | Server-side TUN address. Must parse as IPv4; anything else aborts startup. |
| `-tun-name` | `tiredvpn0` | TUN interface name. |
| `-tun-mtu` | `1280` | TUN MTU. Valid range 1280-9000; outside it startup aborts. The effective per-session MTU is `min(client MTU, this)`. |

`-ip-pool` is required on an **exit** node for TUN-mode clients (`tiredvpn
client -tun`, and the Android app, which is always TUN). Without it the server
logs `TUN mode unavailable: shared TUN not initialized` at boot and rejects
native full-tunnel clients at connect time. A relay (`-upstream`) does not need
it.

`-ip-pool-v6` is validated at startup and rejected unless it is an IPv6 CIDR,
`/96` or shorter (32 host bits are needed to embed the client's IPv4), and
inside `fc00::/7`. Each client's v6 address is its v4 lease embedded in the low
32 bits of the prefix; the server takes `prefix::1`. Only clients handshaking at
protocol version `0x04` or later receive a v6 address.

Package installs set `-ip-pool 10.8.0.0/24` by default (via `TIREDVPN_IP_POOL`
in `/etc/tiredvpn/env`). An empty `TIREDVPN_IP_POOL` (or `--proxy-only`) starts
the server in proxy mode with no pool and no NAT.

### Port hopping

| Flag | Default | Description |
|------|---------|-------------|
| `-port-range` | | Single port (`995`) or range (`47000-47100`) to listen on, TCP and UDP. |
| `-port-range-max` | `50` | Cap on the number of ports opened from a range. |
| `-port-hop-interval` | `1m` | Hop interval advertised to clients during the handshake. |
| `-port-hop-strategy` | `random` | Hint sent to clients: `random`, `sequential`, `fibonacci`. |
| `-port-hop-seed` | | Seed for deterministic hopping, transmitted to clients. |

The server opens every port at once; the client is the side that rotates. A
reversed range (`47100-47000`) is normalised. The `-listen` port is merged into
the set. Deterministic strategies require the same seed on both ends.

### QUIC

| Flag | Default | Description |
|------|---------|-------------|
| `-no-quic` | `false` | Disable the QUIC/UDP listener. QUIC is on by default. |
| `-quic-listen` | *(empty)* | QUIC address. Empty means "the `-listen` address, UDP". |
| `-quic-sni-reassembly` | `false` | Reassemble fragmented SNI in the QUIC Initial. Required for clients using `-quic-sni-frag`. |

At startup the server reads `/proc/sys/net/core/rmem_max` and `wmem_max` and
warns if either is below 7.5 MB. With `-port-range` set, QUIC listens on the
same multi-port set.

### Multi-hop / relay

| Flag | Default | Description |
|------|---------|-------------|
| `-upstream` | | Upstream TiredVPN server, e.g. `exit-node.com:443`. |
| `-upstream-secret` | | Secret used to authenticate to the upstream. Required with `-upstream`. |
| `-relay-idle-timeout` | `0` (= 90s) | Idle deadline for a relay-to-upstream TUN bridge. Silent bridges are force-closed so they stop pinning an admission slot and its buffers. |
| `-relay-upstream-buf` | `0` (= 512 KB) | `SO_RCVBUF`/`SO_SNDBUF` on the TCP dial to the upstream, in bytes. Lower it to bound relay memory. |

A healthy TUN client sends a keepalive every 10 s, so the 90 s default never
trips a live session.

### Admission control and node ceilings

| Flag | Default | Description |
|------|---------|-------------|
| `-max-conns` | `0` | Cap on simultaneously in-flight incoming connections. `0` resolves to `4096` on an exit and `256` on a relay (`-upstream` set). Excess connections are closed immediately, not queued. |
| `-node-max-clients` | `0` (off) | Cap distinct authenticated clients on this node. |
| `-node-max-bytes` | `0` (off) | Cap bytes carried per window. |
| `-node-window` | `1h` | Sliding window the traffic ceiling is measured over. |

Both ceilings default to off; the `tiredvpn_node_*` metrics are exported either
way, so real numbers can be read before a limit is chosen. Enforcement happens
only after a client authenticates, so a prober never observes it.

Two limitations, both logged at startup:

- Transports that authenticate against a single shared secret carry no client
  ID and are not counted, so the live client count can exceed
  `-node-max-clients`.
- On a relay, `-node-max-clients` counts downstream nodes rather than people;
  the traffic ceiling is the meaningful one there.

### REALITY

| Flag | Default | Description |
|------|---------|-------------|
| `-reality-legacy` | `true` | Accept the legacy transport (credentials in padding extension `0x0015`). |
| `-reality-b1` | `false` | Accept the B1 transport: real TLS 1.3, authentication in `session_id`. Requires `-reality-private-key`. |
| `-reality-private-key` | | Server's static X25519 key, base64. Falls back to `TIREDVPN_REALITY_PRIVATE_KEY`. Generate with `tiredvpn reality-keygen`. |
| `-reality-max-time-diff` | `300` | Client clock skew tolerated by B1 auth, in seconds. `0` disables the check; negative aborts startup. |
| `-reality-min-client-ver` | | Lowest client version B1 accepts, `X.Y.Z`. Empty disables the check. An unparsable value aborts startup. |
| `-reality-mirror` | `adaptive` | Donor mirroring for sources that have not authenticated: `off`, `adaptive`, `always`. `always` dials a donor for every connection including real users - measurement only. |
| `-reality-cover-domain` | | Hostname that unauthorised REALITY probes are transparently proxied to (port 443). Empty drops them silently. Operator-set, never derived from the client's SNI. |
| `-reality-require-data-v2` | `false` | Reject clients that do not negotiate the v2 data layer (per-connection keys + AEAD). Turn on only after every client is upgraded. |

Turning both `-reality-b1` and `-reality-legacy` off aborts startup - no REALITY
client could connect. Without `-reality-b1` the server generates an ephemeral
key pair at boot, so B1 clients pinning a public key must not rely on it. With
`-reality-b1` and no key, startup fails rather than silently generating a
throwaway that would drop every client on the next restart. The public half is
printed in the startup log.

### Burst reshaping

| Flag | Default | Description |
|------|---------|-------------|
| `-burst-reshape` | `off` | Split the inner TLS handshake with a nudge/ack exchange so the nDPI burst heuristic stops matching. `off` or `on`. |
| `-burst-reshape-pad-flight` | `0` | Extra bytes added to the server flight. `0` = off. |

Both **must** match the client. There is no negotiation at this layer: a server
that reshapes while the client does not prepends noise to the client's data.
Any value other than `on` is treated as off, so a typo cannot half-enable it.
Counters: `tiredvpn_phase3_*` (see [monitoring.md](monitoring.md)).

### Other transports

| Flag | Default | Description |
|------|---------|-------------|
| `-enable-icmp` | `false` | ICMP tunnel listener. Requires `CAP_NET_RAW`; without it the listener is disabled with a warning rather than an error. |
| `-seqovl-packet-drop` | `false` | Server-side NFQUEUE drop for packet-level `seqovl` overlap. **Not implemented**: setting it logs a warning and forces the value back to false. The client's default safe geometry needs no server-side drop. |

## Environment Variables

| Variable | Read by | Effect |
|----------|---------|--------|
| `TIREDVPN_SECRET` | `-secret` | Shared secret, when the flag is empty. Keeps it out of `ps`/`/proc/*/cmdline`. |
| `TIREDVPN_API_TOKEN` | `-api-token` | Management API bearer token, when the flag is empty. |
| `TIREDVPN_REALITY_PRIVATE_KEY` | `-reality-private-key` | REALITY static key, when the flag is empty. |
| `TIREDVPN_REDIS_DB` | `-redis-db` | Redis database, only when the flag was not passed explicitly. |
| `TIREDVPN_REDIS_PREFIX` | `-redis-prefix` | Redis key namespace, only when the flag was not passed explicitly. |
| `REDIS_PASSWORD` | `internal/server/redis.go` | Redis `AUTH` password. No flag equivalent. |
| `TIREDVPN_WAN_IFACE` | NAT bootstrap | Overrides WAN interface autodetection for MASQUERADE and NAT66. |
| `TIREDVPN_NO_KTLS=1` | `internal/ktls` | Disables kernel TLS offload. |

For flag-backed variables the precedence is flag > env > default.

## Startup Behaviour

### Fatal (the process exits)

- `-tun-ip` is not a valid IPv4 address.
- `-tun-mtu` outside 1280-9000.
- `-ip-pool-v6` is not an IPv6 CIDR, is longer than `/96`, or is not inside `fc00::/7`.
- `-redis-db` (or `TIREDVPN_REDIS_DB`) outside 0-15, or not a number.
- `-config` points at a file that does not parse, fails validation, or contains an unknown field (decoding is strict).
- Neither `-secret`/`TIREDVPN_SECRET` nor `-redis` is set.
- `-redis` set but the connection or the initial registry load fails.
- `-upstream` set without `-upstream-secret`.
- REALITY: unknown `-reality-mirror`, both transports off, negative `-reality-max-time-diff`, unparsable `-reality-min-client-ver`, or `-reality-b1` without a key.
- `-cert`/`-key` cannot be loaded.
- The TCP listener cannot bind.

### Non-fatal (logged, the server keeps running)

- `-enable-icmp` without `CAP_NET_RAW`: the listener is skipped.
- `/dev/net/tun` missing.
- `-seqovl-packet-drop`: warned and forced off.
- NAT or NAT66 bootstrap failure: the server comes up proxy-degraded.
- No `-ip-pool` on an exit node: native full-tunnel clients will be rejected.
- QUIC enabled with UDP buffers below 7.5 MB.
- API bound to a non-loopback address without `-api-token`.
- A forward-hook chain that is not ours has policy `drop` (see below).
- `-node-max-clients` set on a relay.

## Forwarding and NAT (required for TUN mode)

**Automatic, always** - package, container, or the raw binary run by hand.
Whenever `-ip-pool` is set, the server writes `net.ipv4.ip_forward=1` and
installs `MASQUERADE` + `FORWARD` accept rules for the pool on the WAN
interface directly over netlink/nftables. No `iptables`, `ip` or `sysctl`
binaries, no wrapper script or container entrypoint is involved.

The WAN interface is autodetected via the route to `1.1.1.1`; override with
`TIREDVPN_WAN_IFACE`. Rules live in a table named after the pool
(`tiredvpn-nat-10-8-0-0-24`), so several instances on one host do not overwrite
each other, and re-running replaces the table wholesale rather than
accumulating duplicates. Failure is non-fatal: a host without `CAP_NET_ADMIN`
logs a warning and comes up proxy-degraded instead of refusing to start.

With `-ip-pool-v6` the same is done in the `ip6` family: `net.ipv6.conf.all.
forwarding=1`, NAT66 MASQUERADE and forward-accept for the ULA prefix in a
`tiredvpn-nat6-*` table. The v6 uplink is detected via the IPv6 route
(`2606:4700:4700::1111`), not the IPv4 one, because an exit whose IPv6 arrives
over a tunnel broker egresses v6 on a different interface. Enabling forwarding
makes the kernel ignore Router Advertisements, so the uplink's
`accept_ra` is raised from `1` to `2` to keep an RA-learned default route from
expiring; `0` and `2` are left alone.

One case the automatic setup cannot fix: nftables evaluates **every** base chain
on a hook, and an accept verdict in our table does not override a `drop` policy
in somebody else's (an `iptables-nft` FORWARD chain, a firewall's own table,
Docker). The server detects this at startup and warns; add an explicit rule
there yourself. We do not edit a table we do not own.

The packaged unit (`install.sh`, one-liner, apt/dnf) sets TUN mode by default:
the env file gets `TIREDVPN_IP_POOL=10.8.0.0/24` and the unit starts the server
with `-ip-pool ${TIREDVPN_IP_POOL}`. Opt out with `install.sh --proxy-only` /
`tiredvpn-init --proxy-only`, or set `TIREDVPN_IP_POOL=` (empty) in
`/etc/tiredvpn/env` and restart. Custom CIDR: `tiredvpn-init --ip-pool <CIDR>`.

If you would rather manage NAT yourself, that is fine: the automatic setup only
ever touches the `-ip-pool` CIDR, so your own rules coexist with it. See
[Server firewall and forwarding](../README.md#server-firewall-and-forwarding-required-for-tun-mode)
in the README for manual commands.

## Configuration via TOML

`-config <path>` loads a TOML file. Decoding is strict: an unknown key is an
error, so typos surface at startup instead of being ignored.

```bash
tiredvpn server --config /etc/tiredvpn/server.toml
```

A copy-paste template lives in
[`configs/server.example.toml`](../configs/server.example.toml).

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
mode = "token"
tokens_file = "/etc/tiredvpn/tokens.txt"

[logging]
level = "info"
```

### Schema

| Key | Required | Validated | Applied at runtime |
|-----|----------|-----------|--------------------|
| `listen.address` | yes | non-empty | yes -> `-listen` host |
| `listen.port` | yes | 1-65535 | yes -> `-listen` port |
| `strategy.mode` | yes | non-empty | **no** |
| `strategy.options` | no | - | **no** |
| `tls.cert_file` | yes | non-empty | yes -> `-cert` |
| `tls.key_file` | yes | non-empty | yes -> `-key` |
| `tls.alpn` | no | - | **no** |
| `tls.client_ca_file` | no | - | **no** |
| `auth.mode` | yes | non-empty | **no** |
| `auth.tokens`, `auth.tokens_file` | no | - | **no** |
| `logging.level` | no | - | partially: `"debug"` enables debug logging |
| `logging.format`, `logging.output` | no | - | **no** |
| `shaper.*` | no | preset/custom are mutually exclusive | stored, **not consumed** (see below) |

The keys marked "no" are accepted and validated by the schema but are not wired
into `server.Config`. In particular `[auth]` does **not** configure
authentication - clients still authenticate against `-secret` or the Redis
registry - and `strategy.mode` does not select a transport. Do not use the TOML
file as the authentication source. The gaps are enumerated in
`applyServerTOMLConfig` (`cmd/tiredvpn/config.go`) and in the
[migration guide](../internal/config/toml/MIGRATION.md).

### Precedence

Defaults < TOML < CLI, but only for the four flags that have a TOML
counterpart: `-listen`, `-cert`, `-key`, `-debug`. A flag wins only when it was
passed explicitly (`flag.Visit`), so a flag left at its default never
overwrites a TOML value.

Every other flag is unaffected by `-config` in either direction: it is read
straight from the command line, and no TOML key can set it. Redis
multi-tenancy, the IP pool, port hopping, REALITY, node ceilings and the
monitoring endpoints are all command-line only.

## Traffic Shaper (server side)

The server does **not** choose its own shaper. For morph strategies it reads a
one-byte shaper ID that trails the client's auth token and reconstructs the
matching preset; an absent, unknown or noop ID leaves the connection on the
legacy byte-relay framing. So server-to-client framing follows whatever the
client negotiated.

A `[shaper]` block in the server TOML is parsed and validated, and the built
shaper is stored on `server.Config.Shaper`, but nothing reads that field yet -
setting it changes no bytes on the wire. Preset names and trade-offs are
documented on the client side: [client.md -> Traffic Shaper](client.md#traffic-shaper).

## Fake website

Anything that reaches the listener without valid credentials gets an
nginx-shaped HTTP response - matching `Server` header, header order, `ETag`,
`Last-Modified`, `Accept-Ranges`, and the same behaviour over HTTP/1.1 and
HTTP/2.

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

Resolution rules:

- `-fake-root` exists and the requested path resolves inside it: the file is
  served with its detected MIME type, `200`. A directory falls back to its
  `index.html`.
- `-fake-root` exists but the path does not: the built-in nginx welcome page for
  `/` and `/index.html`, a byte-exact nginx `404` for anything else.
- `-fake-root` missing or not a directory (the `./www` default usually is): the
  built-in welcome page for `/`, `404` for everything else - a freshly installed
  nginx.

Paths are cleaned and confined to the root, so `../` traversal returns `404`.

## Configuration Examples

### Minimal single-client

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret $(openssl rand -hex 32)
```

### Dual-stack transport (IPv4 + IPv6)

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret>
```

### Multi-client with Redis, TUN pool and IPv6 in the tunnel

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -api-addr 127.0.0.1:8080 \
  -api-token <token> \
  -ip-pool 10.8.0.0/24 \
  -ip-pool-v6 fd00:10:8::/64
```

### Second instance on the same Redis

```bash
tiredvpn server \
  -listen :994 \
  -cert server.crt \
  -key server.key \
  -redis localhost:6379 \
  -redis-db 1 \
  -redis-prefix tiredvpn-relay:
```

### Port hopping

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret> \
  -port-range 47000-47100 \
  -port-range-max 50 \
  -port-hop-interval 1m \
  -port-hop-strategy random
```

Clients must enable `-port-hop` with matching range parameters.

### Multi-hop relay

```bash
tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <relay-secret> \
  -upstream exit-node.example.com:443 \
  -upstream-secret <upstream-secret> \
  -relay-upstream-buf 262144
```

### REALITY B1 with a static key

```bash
tiredvpn reality-keygen   # prints the pair; keep the private half out of argv

TIREDVPN_REALITY_PRIVATE_KEY=<private> tiredvpn server \
  -listen :443 \
  -cert server.crt \
  -key server.key \
  -secret <secret> \
  -reality-b1 \
  -reality-cover-domain www.microsoft.com
```

Clients need `-reality-server-pubkey <public>`.

## Management API

In multi-client mode the REST API listens on `-api-addr`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/clients` | List clients |
| `POST` | `/clients` | Create a client |
| `GET` | `/clients/{id}` | Client detail and stats |
| `DELETE` | `/clients/{id}` | Delete a client |
| `GET` | `/stats` | Aggregate stats |
| `GET` | `/health` | Health, including a Redis ping |
| `GET` | `/metrics` | Prometheus metrics |

There is no update endpoint: a client's fields cannot be changed through the
API. See [admin.md](admin.md) for request and response bodies and
[monitoring.md](monitoring.md) for the metric names.
