# Architecture

This document describes how TiredVPN is put together: what happens between an
application socket and the exit node, and why the pieces are arranged the way
they are. For flags, see [Server Reference](server.md) and
[Client Reference](client.md); for the transports themselves, see
[DPI Bypass Strategies](strategies.md).

## What it is

TiredVPN is a censorship-circumvention tool, not a traditional VPN. There is no
WireGuard, OpenVPN or IPsec here. The client is a user-space process that takes
traffic in one of two ways — a SOCKS5/HTTP proxy listener, or a TUN device that
captures the host's routing table — and carries it to the server over one of
about twenty obfuscated transports, picking whichever one the current network
lets through.

Two consequences follow from that design and explain most of what is below.
First, the transport is chosen at runtime and can change mid-session, so nothing
above it may assume a particular wire format. Second, the transport's job is to
be unremarkable to a middlebox, which is a different goal from being secure
against one — see [Security Model](security.md) for where those two come apart.

## The layers

```
   applications ──▶ SOCKS5 / HTTP listener ──┐
                                             │
   host routes  ──▶ TUN device (tiredvpn0) ──┤
                                             ▼
                          ┌──────────────────────────────────┐
                          │ endpoint.Selector                │  which server,
                          │                                  │  which family
                          └────────────────┬─────────────────┘
                          ┌────────────────▼─────────────────┐
                          │ strategy.Manager                 │  probe, rank,
                          │                                  │  circuit-break
                          └────────────────┬─────────────────┘
                          ┌────────────────▼─────────────────┐
                          │ transport: REALITY, HTTP/2 stego,│
                          │ QUIC, morph, WebSocket, polling, │
                          │ ICMP, ...                        │
                          └────────────────┬─────────────────┘
                                           │  smux streams inside
                                       (network)
                          ┌────────────────▼─────────────────┐
                          │ classify → authenticate → relay  │  tiredvpn server
                          └────────────────┬─────────────────┘
                                           │
                             shared TUN + NAT, or TCP relay,
                             or an upstream hop
```

## Code layout

```
cmd/tiredvpn/          CLI entry point, TOML loading, JNI shims
internal/
  client/              client orchestration, SOCKS5 + HTTP proxy, TUN mode entry
  server/              listeners, protocol classification, auth, relay, shared TUN, REST API
  strategy/            strategy manager and ~20 transport implementations
  endpoint/            server pool: candidate ranking, health, cooldown, family policy
  tls/                 uTLS fingerprints, REALITY auth and extension, ECH, PQ primitives
  tun/                 TUN device, routes, MTU probing, NAT, IPv6 policy
  mux/                 smux configuration and metrics
  pool/                client-side tunnel pool for proxy requests
  protocol/            the one-byte protocol discriminator sent after the handshake
  padding/             Salamander packet obfuscation
  evasion/             fragmentation, SNI rotation, fake packets, donor SNI lists
  geneva/              Geneva packet-manipulation engine
  porthopping/         port hopping schedule
  shaper/              traffic-shaping abstraction used by the morph transports
  detect/              offline reimplementation of nDPI's obfuscated-TLS heuristic
  ktls/                kernel TLS offload (Linux)
  capabilities/        startup probe for CAP_NET_ADMIN / CAP_NET_RAW / /dev/net/tun
  config/toml/         TOML schema, defaults and CLI override rules
  control/             control-channel protocol (0xCC magic byte) and Android IPC
  protect/             Android VpnService socket protection
  metrics/, log/       Prometheus metrics, structured logging
  benchmark/           strategy benchmarking harness
```

## Client startup

`cmd/tiredvpn` parses flags, optionally merges a TOML file, and calls
`client.Run`. The order of the first few steps matters:

```
client.Run
  ├── ResolveEndpoints()     [[servers]] from TOML, or the single -server
  ├── resolveSecret()        flag, then TIREDVPN_SECRET, then an insecure default
  ├── buildManager()         registers strategies, builds the endpoint selector
  └── runTUNMode() | runProxyMode() | runControlSocketMode()
```

`ResolveEndpoints` runs first because it is what fills `cfg.ServerAddr` when the
client was configured with a server list rather than a single address.

## Choosing where to dial

Before 1.5.0 the client had one server address and decided its address family
once, at startup. Both are now the same thing: a dial target is a *candidate*,
meaning one endpoint on one address family, and `internal/endpoint` ranks the
candidates.

```
[[servers]] × {IPv6, IPv4}  ──▶ candidate list, endpoint-major order
                                  │
                       Selector.Reconsider()  → current candidate
                                  │
                    connect fails twice in a row
                                  │
                       candidate parked, exponential cooldown,
                       jittered expiry, dwell window before the
                       preferred one is retried
```

Falling back from IPv6 to IPv4 within one server is tried before moving to
another server: same secret, same bypass route, same latency profile. Candidate
order comes from `[selection]` — `priority` (as written), `latency` (measured
EWMA, ranking endpoints rather than families so a slow path cannot override
`prefer_v6`), or `weighted`, which is sticky because reselecting per dial would
show up on the wire as flapping between addresses.

One dial may try at most two candidates (`maxEndpointAttempts`). A reconnect has
about 15 seconds to complete and each candidate costs a full strategy scan, so a
deeper walk would turn one dead family into a minutes-long outage.

There is also a pre-flight gate. It runs on the first connect, and again once
several connects in a row have failed — not on every reconnect, where it would
only add latency. When it runs it probes the whole pool, so if the pinned
address is silent and another answers, the selector switches to that one
instead of walking every strategy against a black hole.

## Choosing a transport

`strategy.Manager` holds the registered strategies. `ProbeAll` runs their
`Probe` methods in parallel and ranks them by success rate and latency;
`Connect` then walks the ranked list until one returns a connection. Each
strategy carries a circuit breaker, so a transport that keeps failing is skipped
for a cooldown rather than retried on every request.

Two behaviours worth knowing about:

- **Storm detection.** Sessions that keep dying shortly after connecting look
  like DPI tearing down a pattern rather than like a flaky network. The manager
  parks that strategy and fails over instead of reconnecting into the same wall.
- **Periodic reprobing** (`-reprobe-interval`, default 5 minutes) re-ranks
  strategies while a session is up, so a transport that was blocked at startup
  can be picked up later.

## A proxy request

```
SOCKS5 / HTTP CONNECT arrives
  └── pool.TunnelPool.DialTarget()
        └── strategy.Manager.Connect()      new transport connection
              └── [addrLen:2][target address]
                    └── server replies 0x00 (ok) or 0x01 (refused)
                          └── bytes relayed both ways
```

Pool connections are single-use. That is deliberate rather than an oversight:
reusing a connection for a second request was observed being throttled by TSPU
after the idle gap between them, so every request pays a fresh handshake
instead. The comment in `internal/strategy/reality.go` records both the original
measurement and why it has not been re-taken since the configuration changed.

## Server side: classification

The server does not know which transport is arriving, so it classifies before it
authenticates. `readFirstPeek` reads one full TLS record — or up to about 2 KiB
for non-TLS — under a short deadline, so a peer that connects and says nothing
cannot pin a goroutine.

```
accept
  └── readFirstPeek
        ├── HTTP/2 preface       → handleHTTP2
        ├── "MRPH"               → morph
        ├── 0x16 (TLS record)
        │     ├── REALITY B1     (if -reality-b1: auth parsed out of session_id)
        │     ├── REALITY legacy (if -reality-legacy: padding extension 0x0015)
        │     └── otherwise      crypto/tls handshake, then one encrypted
        │                        dispatch byte selects the handler
        └── anything else        timing knock / SSH / IMAP camouflage /
                                 protocol confusion / fake website
```

The dispatch byte (`internal/protocol`) is a single value sent after the TLS
handshake: `0x01` stego, `0x02` raw, `0x03` morph, `0x04` WebSocket, `0x05`
polling, `0x06` confusion, `0x07` anti-probe, `0x08` smux. It sits inside the
encrypted stream because ALPN, the obvious alternative, is cleartext in the
ClientHello.

Two of the fallbacks are there to avoid standing out rather than to serve
anyone. A ClientHello that fails the REALITY check is handed back to the
ordinary TLS path instead of being dropped, because OpenSSL adds a real padding
extension to any ClientHello between 256 and 511 bytes, and answering that with
a FIN identified our servers in one packet. A failed TLS handshake is closed
rather than answered, because replying to a broken handshake with a plaintext
HTTP response did the same thing.

Once a transport has authenticated its client, everything converges on
`handleRawTunnel`, which reads one mode byte:

```
0x02  → TUN mode: [localIP:4][mtu:2][version:1] handshake, then framed packets
else  → proxy mode: the byte was the high half of a 2-byte address length
```

The node ceiling (`-node-max-clients`, `-node-max-bytes`) is enforced here, not
at accept, so a peer that cannot authenticate never gets to measure it.

## Authentication

There are three schemes in the tree, and which one applies depends on the
transport.

**REALITY, legacy path.** The client puts `[X25519 pubkey:32][token:32]` at the
start of a 256-byte TLS padding extension. The token is
`HMAC-SHA256(secret, clientPubKey || timestamp_bucket)` over 5-minute buckets,
accepted within ±1 bucket. Binding to a per-connection public key is what keeps
a captured token from being replayed onto another connection. The server answers
with `HMAC-SHA256(secret, clientPubKey || "reality-server-ack")` inside the
ServerHello padding, which is how the client tells our server from a middlebox
that has no secret.

**REALITY B1** (`-reality-b1` on the server, `-reality-server-pubkey` on the
client). Authentication travels in the 32 bytes of `legacy_session_id` that
every TLS 1.3 ClientHello already carries, sealed with a key derived from the
client's ephemeral X25519 key share and the server's static public key, with the
marshalled ClientHello as associated data. The handshake itself is a real TLS
1.3 handshake; see [Security Model](security.md) for what that changes.

**Everything else** (HTTP/2 stego, morph, WebSocket, polling, anti-probe) sends
`HMAC-SHA256(secret, minute_bucket || "http2-stego-auth")` in a
transport-appropriate place — an HTTP/2 header, a handshake field, an HTTP
header. The server accepts ±10 minutes of clock skew.

In multi-client mode the server holds per-client secrets in Redis
(`internal/server/registry.go`) and tries each one in turn against the presented
token; deleting a client from Redis revokes it immediately. Without Redis there
is one global secret.

## Stream multiplexing

REALITY runs [smux](https://github.com/xtaci/smux) inside the transport, so one
TCP connection carries many streams. On the server each accepted stream is
handed to `handleRawTunnel` independently.

```
one REALITY connection
  ├── stream 1  → CONNECT to target A
  ├── stream 2  → CONNECT to target B
  └── stream 3  → the TUN tunnel
```

The two paths configure smux differently, on purpose. The legacy path uses
`smux.DefaultConfig()`, whose 10-second keepalive NOP is itself a timing
signature. B1 uses `mux.SmuxSilentConfig()` — no keepalive sent, none expected —
which is safe there only because B1 has never shipped in a release, so both ends
of a B1 session are guaranteed to be the same build.

Separately, `internal/mux` provides a manager-level mux layer with its own
keepalive and carrier-budget settings, used when mux is enabled at the manager
rather than inside a strategy.

The control channel (`internal/control`) multiplexes control messages with data
using a `0xCC` magic-byte prefix.

## TUN mode

With `-tun` the client creates `tiredvpn0` (or adopts a file descriptor passed
as `-tun-fd`, which is how Android's `VpnService` hands over its interface),
assigns an address, and points routes at it. The routes go up only after the
first connection and handshake have succeeded — otherwise a failed start would
leave the host with a default route into a dead interface.

Packets are framed with a 4-byte big-endian length:

```
TUN read → ClampTCPMSS → [len:4][ip packet] → transport → server
```

The handshake is `[0x02][localIP:4][mtu:2][version:1]`. The version byte is the
negotiation: `0x03` means the client understands active MTU probing, `0x04` adds
IPv6 dual-stack. A server that predates a version answers with the older
response layout, and the client copes.

`-auto-mtu` measures the working MTU end to end by sending probe frames the exit
echoes, rather than assuming one. This exists because a relay chain silently
black-holed oversized frames.

### On the server

The server does not create one TUN device per client. `SharedTUN`
(`internal/server/shared_tun.go`) owns a single interface and dispatches inbound
packets to clients by destination IP through a worker pool. Addresses come from
`-ip-pool`, leased per client and returned on disconnect.

NAT is installed through netlink and nftables directly
(`internal/tun/nat_linux.go`) rather than by shelling out to `iptables`. Each
pool gets its own table, named after the CIDR, because a single shared table
meant every instance on a multi-instance host wiped the others' rules at
startup.

### IPv6 inside the tunnel

Since 1.5.0 `-tun-ipv6` defaults to `dual`. The client advertises handshake
version `0x04`; if the exit has `-ip-pool-v6` configured it answers with
`[serverIP6:16][clientIP6:16]`, derived from the prefix with the client's IPv4
lease in the low 32 bits — which is what lets the server route both families
from one registry keyed by the IPv4 address.

If the exit cannot carry IPv6, the client blocks outbound IPv6 for the life of
the tunnel with a per-interface nftables table in the `ip6` family, hooked at
output. Loopback, the tunnel, link-local, multicast and the server's own IPv6
addresses stay reachable; everything else is rejected with ICMPv6
admin-prohibited so applications fail over to IPv4 immediately instead of
waiting out a timeout. The reason for blocking rather than ignoring: with a
working IPv6 default route on the host, every application reached the internet
outside the tunnel and handed out the user's real address.

This is Linux-only. On macOS the gap is reported with a warning; on Android the
filtering belongs to `VpnService`.

## Multi-hop

```
client → relay (-upstream exit:443) → exit → internet
```

A server started with `-upstream` dials the next hop as a client and forwards
authenticated traffic through it. The client sees only the relay, and needs only
the relay's secret. `UpstreamDialer` keeps a TLS session cache for faster
reconnects and pins socket buffers at 512 KiB per upstream dial — on a relay
that is a direct per-connection memory multiplier, and a larger value was the
main contributor to relay OOMs.

## Android

The client builds as a shared library (`make build-android`) with the JNI entry
points in `cmd/tiredvpn/jni_android.go`. The app passes the TUN file descriptor
from `VpnService.establish()` as `-tun-fd`, and a Unix socket path as
`-protect-path`; the client calls back through that socket so `VpnService`
can exclude the tunnel's own sockets from the routing loop. Android mode also
turns off raw sockets, ICMP and `os/exec` route manipulation, none of which are
available inside the sandbox.

## Metrics

`internal/metrics` and the per-area metric files under `internal/server` and
`internal/client` export Prometheus text format at `-api-addr`: per-strategy
success rate and latency, DPI-detection events, smux stream counts, TUN packet
and byte counters, MTU probe outcomes, IPv6 dispatch outcomes, and the usual
runtime numbers. See [Monitoring](monitoring.md).
