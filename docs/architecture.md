# Architecture

This document describes TiredVPN's internal design.

## Overview

TiredVPN is a censorship-circumvention tool, not a traditional VPN. It does not implement WireGuard, OpenVPN, or IPsec. Instead it runs a user-space proxy that can operate in SOCKS5/HTTP mode or as a TUN-based full tunnel, with an adaptive strategy engine that picks the best obfuscation transport for the current network.

```
┌─────────────────────────────────────────┐
│           Application / OS              │
│  (SOCKS5 proxy)         (TUN mode)      │
└────────────┬────────────────┬───────────┘
             │                │
┌────────────▼────────────────▼───────────┐
│              tiredvpn client            │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │       Strategy Manager           │   │
│  │  probe → rank → select → monitor │   │
│  └──────────────┬───────────────────┘   │
│                 │ best strategy         │
│  ┌──────────────▼───────────────────┐   │
│  │         smux multiplexer         │   │
│  └──────────────┬───────────────────┘   │
│                 │ streams               │
│  ┌──────────────▼───────────────────┐   │
│  │      Transport / Evasion Layer   │   │
│  │  QUIC │ TLS │ WS │ HTTP2 │ ICMP  │   │
│  └──────────────┬───────────────────┘   │
└─────────────────┼───────────────────────┘
                  │  encrypted, obfuscated
               (network)
                  │
┌─────────────────┼───────────────────────┐
│            tiredvpn server              │
│                                         │
│  ┌──────────────▼───────────────────┐   │
│  │     TCP (TLS) + UDP (QUIC)       │   │
│  │     Listeners (IPv4 + IPv6)      │   │
│  └──────────────┬───────────────────┘   │
│                 │ authenticated conn     │
│  ┌──────────────▼───────────────────┐   │
│  │         smux multiplexer         │   │
│  └──────────────┬───────────────────┘   │
│                 │ streams               │
│  ┌──────────────▼───────────────────┐   │
│  │      Relay / TUN / Upstream      │   │
│  └──────────────┬───────────────────┘   │
└─────────────────┼───────────────────────┘
                  │
              Internet
```

## Code Layout

```
cmd/tiredvpn/          CLI entry point (main.go, jni.go)
internal/
  server/              Server: TLS/QUIC listeners, auth, relay, API
  client/              Client: proxy, TUN, strategy orchestration
  strategy/            Adaptive strategy engine + 20+ implementations
  evasion/             Low-level primitives: fragmentation, SNI rotation, fake packets
  tunnel/              gRPC and WebSocket tunnel abstractions
  tun/                 TUN interface management (Linux)
  mux/                 smux multiplexer integration
  proxy/               SOCKS5 + HTTP proxy server
  tls/                 uTLS fingerprinting, REALITY, ECH, post-quantum
  ktls/                Kernel TLS offload (Linux)
  padding/             Salamander traffic padding
  evasion/             TCP fragmentation, QUIC SNI frag, fake packets
  geneva/              Geneva packet manipulation engine
  porthopping/         Port hopping logic
  multiport/           Multi-port UDP with ARQ reassembly
  pool/                IP address pool for TUN clients
  metrics/             Prometheus metrics
  config/              Configuration types
  log/                 Structured logging
  control/             Android IPC protocol
  protect/             Android VpnService socket protection
  benchmark/           Strategy benchmarking
```

## Connection Flow

### 1. Client startup

```
main.go → client.New(config) → client.Start()
    │
    ├── StartProxy()          starts SOCKS5/HTTP listener
    ├── StartStrategyManager()
    │       └── ProbeAll()    parallel probes of all strategies
    │               └── SelectBest()  rank by latency × success_rate
    └── (if -tun) SetupTUN()  create tun device, add routes
```

### 2. Incoming proxy connection

```
SOCKS5/HTTP request
    │
    └── client.handleConn()
            └── strategy.Dial(target)
                    └── smux.OpenStream()
                            └── transport.Write(stream)
                                    └── [obfuscated bytes on wire]
```

### 3. Server side

```
TLS Accept() / QUIC Accept()
    │
    └── server.handleConn()
            ├── authenticateClient(secret)    HMAC verify
            └── smux.Server()
                    └── for each stream:
                            └── relay.Dial(target)  → Internet
```

## Authentication

TiredVPN uses HMAC-SHA256 with time-bucketed tokens for replay protection:

```
token = HMAC-SHA256(secret, timestamp_bucket || context)
timestamp_bucket = unix_timestamp / 300   (5-minute windows)
```

The client sends the auth token in the first message of each connection. The server verifies it and rejects connections with tokens outside the ±1 bucket window.

In multi-client mode (Redis), each client has a unique secret. The server looks up the secret by performing `ClientRegistry.GetBySecret(token_prefix)`.

## Stream Multiplexing

All streams between client and server share a single underlying connection via [xtaci/smux](https://github.com/xtaci/smux). This avoids the handshake overhead of opening a new TLS/QUIC connection per user request.

```
Connection (1 per strategy)
  ├── Stream 1  →  user request A
  ├── Stream 2  →  user request B
  └── Stream 3  →  control channel (PING/PONG/STATS)
```

The control channel uses magic byte `0xCC`. It carries keepalive pings and statistics requests independently of data streams.

## Salamander Padding

Salamander ([paper](https://arxiv.org/abs/2407.02996)) pads QUIC Initial packets to a uniform size, removing the packet-length fingerprint used by deep packet inspection.

```
Original QUIC Initial: 300 bytes
After Salamander (Balanced): padded to 1350 bytes with encrypted noise
```

Three padding levels are available (Conservative / Balanced / Aggressive), trading overhead for stealth.

## TUN Mode

When `-tun` is enabled, the client:

1. Creates a TUN device (`tiredvpn0` by default) via `/dev/net/tun`
2. Assigns the local TUN IP (`-tun-ip`, default `10.8.0.2`)
3. Adds routes from `-tun-routes` pointing to the TUN interface
4. Reads packets from the TUN device, wraps them in the VPN tunnel
5. Receives packets from the server, writes them to the TUN device

The server creates its own TUN device and performs NAT for client packets.

Android uses the same mechanism but via `VpnService.establish()` which provides a pre-configured TUN fd passed with `-tun-fd`.

## Multi-Hop

```
Client → Server A (-upstream exit.com:443) → Server B → Internet
```

Server A connects to Server B as a client during startup. Client traffic is forwarded through Server A → Server B transparently. The client only needs to trust Server A's certificate.

Useful for:
- Adding a hop in a different jurisdiction
- Separating the ingress server (in a censored country) from the exit node

## Android Integration

The Android SDK wraps `tiredvpn` as a C shared library (`libtiredvpn.so`) built with `make build-android`. The JNI entry point is in `cmd/tiredvpn/jni.go`.

The Android VpnService communicates with the library over a Unix socket (`-control-socket`):

```
Android App → Unix socket → control.go → client.go
                                │
                                └── protect-path socket
                                    (calls VpnService.protect() to exclude VPN traffic from routing loop)
```

## Metrics

The metrics system (`internal/metrics/`) tracks:

- Per-strategy success rate, latency, and DPI-detection events
- smux stream counts and errors
- TUN packet counters
- Runtime metrics (goroutines, memory)

Exposed as Prometheus text format at `-api-addr /metrics`. See [monitoring.md](monitoring.md).
