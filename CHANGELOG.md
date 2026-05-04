# Changelog

All notable changes to TiredVPN are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-05-04

### Added

- **Traffic Shaper** — new behavioural masking layer (`internal/shaper`) that decouples DPI shape from TLS transport. Distribution engines (Histogram, LogNormal, Pareto, MarkovBurst), four ready-made presets (`chrome_browsing`, `youtube_streaming`, `random_per_session`, `bittorrent_idle`) and a `cmd/shaper-dump` utility for χ² / Jupyter visualization.
- **TOML configuration** — `tiredvpn client|server --config <path>` (`internal/config/toml`). Strict validation via `pelletier/go-toml/v2 DisallowUnknownFields`, precedence CLI > TOML > defaults, full field reference in [`internal/config/toml/MIGRATION.md`](internal/config/toml/MIGRATION.md).
- Example configs: [`configs/client.example.toml`](configs/client.example.toml), [`configs/server.example.toml`](configs/server.example.toml). Regression-tested by `TestExampleConfigs_LoadCleanly`.
- `presets.IsDataPlaneSafe(name)` accessor and `DataPlaneSafe` flag on every registered preset.
- `presets.ByNameAllowAny` entry point for cover-traffic callers that need access to non-data-plane presets.
- Real-tunnel TCP e2e test (`internal/integration/tunnel_e2e_test.go`, build tag `integration_e2e`) that loads both sides from TOML and verifies byte-perfect 1 MiB roundtrip.
- Documentation: [`docs/client.md`](docs/client.md) and [`docs/server.md`](docs/server.md) gained "Configuration via TOML" and "Traffic Shaper" sections; [`internal/shaper/README.md`](internal/shaper/README.md) carries the final performance table.

### Performance

- Shaped-write throughput on `chrome_browsing` improved **109×** (1.75 → ~191 MB/s on loopback TCP, 16 MiB workload). Heap traffic dropped **12×** (~70 MB → ~5.8 MB per transfer), allocations −24%.
- The pipeline now runs an async pacer goroutine with sleep coalescing, adaptive throttling on queue overflow, a 50 ms inter-frame delay cap, and `writev` (`net.Buffers`) coalescing. Frame buffers are pulled from a 4-bucket `sync.Pool`; `Wrap` and `Unwrap` reuse output slices via a new `Shaper.Release` method.
- Honest trade-off: ~80% throughput overhead vs. unshaped Noop remains in the pacer goroutine handoff. Operators who do not need DPI shape masking should omit `[shaper]` from their TOML — the rest of the anti-DPI stack (REALITY, port-hop, RTT masking) is fully effective on its own.

### Breaking

- Shaper preset `bittorrent_idle` is no longer accepted in data-plane configs (`shaper.preset = "bittorrent_idle"` returns `ErrPresetNotDataPlaneSafe`). Its ~7 s median inter-arrival is suitable for cover-traffic generation only; cover-traffic emitters must call `presets.ByNameAllowAny`. `random_per_session` now picks only from data-plane-safe basis presets.

### Changed

- `version` is now passed through `-ldflags` from `git describe` at release build time. Local development builds report `dev`.

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
