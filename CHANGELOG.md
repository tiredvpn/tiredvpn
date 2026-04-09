# Changelog

All notable changes to TiredVPN are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.3] - 2026-04-09

### Added

- **E2E integration testing in CI** — server starts on localhost, client connects via SOCKS5, real HTTP requests verified through the tunnel
- **Strategy benchmark in CI** — 19 strategies probed against localhost server on every push
- **Integration test job** — runs porthopping, QUIC Salamander, mux, and server tests without `-short` flag
- README: comparison table with other VPN tools, community links, star history badge

### Fixed

- Fixed WebSocket Padded integration tests — server address was discarded (`_ = addr`), now passed via Manager
- Fixed `TestDefaultPaddingMode` — assertion updated to match actual default (Minimal)
- Fixed `TestConfusedConnWrite` data race — replaced shared variable with channel synchronization
- Pinned `trivy-action` from `@master` to `@v0.35.0` (supply chain hardening)
- Removed Telegram links from README community section

## [1.0.2] - 2026-04-08

### Changed

- Upgraded smux from v1.5.57 to v2.0.1 — improved multiplexing performance
- Upgraded Docker CI actions: setup-buildx v4, build-push v7, login v4
- Added test coverage reporting to CI pipeline
- Release workflow now gates on passing tests and lint before building artifacts

## [1.0.1] - 2026-04-05

### Fixed

- Fixed `ktls.Enable()` return type on non-Linux platforms (was `bool`, now `*Conn`)
- Applied `gofmt -s` formatting across all Go files

### Changed

- Refactored `server.Run()`, `handleHTTP2()`, `strategy.NewDefaultManager()`, `client.Run()`, `tun.RunTUNRelayWithCallbacks()` — extracted helpers to reduce cyclomatic complexity
- Removed darwin/windows from release builds (TUN requires Linux kernel)

## [1.0.0] - 2026-04-03

### Added

- **Adaptive strategy engine** — probes available transports, ranks by latency/reliability, falls back seamlessly mid-session
- **20+ DPI bypass strategies**:
  - REALITY — impersonates real TLS handshakes of legitimate websites
  - QUIC Salamander — UDP transport with packet padding to defeat traffic analysis
  - HTTP/2 Steganography — tunnel data inside real HTTP/2 frames
  - WebSocket Padded — WebSocket framing with random padding
  - Traffic Morphing — statistically matches CDN/streaming traffic patterns
  - Protocol Confusion — mixes protocol signatures to confuse DPI classifiers
  - Geneva — country-specific packet manipulation (Russia, China, Iran, Turkey)
  - HTTP Polling — covert data transfer over chunked HTTP responses
  - Anti-Probe — active probe detection and response
  - State Exhaustion — forces DPI state machine resets
  - ECH (Encrypted Client Hello) — hides SNI from deep inspection
  - TLS Mimicry — mirrors TLS fingerprints of popular browsers
  - QUIC SNI Fragmentation — splits SNI across multiple QUIC packets
  - Mux (smux) — multiplexed streams over a single connection
  - RTT Masking — randomizes inter-packet timing
  - ICMP Tunnel (stealth) — data transport over ICMP echo
  - Port Hopping — random, sequential, and Fibonacci port rotation
  - IPv6 Transport — dual-stack with automatic fallback
  - Mesh — distributed relay network
- **Post-quantum cryptography** — ML-KEM-768 (key encapsulation) + ML-DSA-65 (signatures)
- **TUN mode** — full system traffic tunneling (Linux)
- **SOCKS5 and HTTP proxy** modes
- **Multiplexed connections** via smux for efficient stream management
- **Client management** — Redis backend, REST API, QR code generation for mobile provisioning
- **Docker support** — multi-stage builds for minimal images
- **Prometheus-compatible metrics** endpoint
- **Android JNI integration** — compiled as `c-shared` for embedding in the Android client
- **Multi-hop routing** — chain multiple servers for additional anonymity
- **ALPN-based routing** — single port serves multiple protocols transparently
- **Fake website** — unauthenticated visitors see a real-looking HTTPS site; the server is indistinguishable from nginx
