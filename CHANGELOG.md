# Changelog

All notable changes to TiredVPN are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.17] - 2026-07-01

### Fixed

- **Spurious 502 / connection failure on the proxy path.** Each proxied request opens a fresh tunnel connection (a new connection per request is deliberate — it avoids the TSPU throttle that drops a second stream reused on the same TCP). Occasionally a just-opened connection lost the race against a transient server-side stream teardown and died before the server's acknowledgement byte, surfacing to the user as `No response from server: EOF` and an immediate 502 (or SOCKS failure). The proxy handlers now go through a single dial helper that, on such a transient failure (connect error, write error, or EOF before the ack), transparently retries once with a brand-new connection before giving up. A deliberate server-side rejection (non-zero ack) is still surfaced immediately without a retry, and connections are never reused — the one-TCP-per-request DPI property is preserved.

## [1.3.16] - 2026-06-30

### Fixed

- **Relay memory exhaustion under load (OOM crash loop).** A relay node (`-upstream`) holds a full per-client upstream bridge, and three compounding issues let those bridges pile up in RAM until the OOM killer reaped the process every ~15 seconds on a memory-tight box, tearing down every tunnel through it. (1) Each upstream dial committed 8 MB of socket buffers (4 MB SO_RCVBUF + 4 MB SO_SNDBUF); on a slow upstream leg the send buffer stayed full of undrained data. Bounded to 512 KB (configurable via `RelayUpstreamBufBytes`). (2) The relay→upstream copy had no idle deadline, so a silently-vanished downstream (lost link, half-open connection) left the copy blocked on read forever, pinning an admission slot, the upstream connection and its buffers — `SetReadDeadline` could not reap it because an h2 TUN downstream ignores deadlines. Added an idle watchdog that force-closes a bridge after 90 s with no traffic in either direction; live sessions are kept fresh by the existing 10 s TUN keepalive (configurable via `RelayIdleTimeout`). (3) The 4096 admission limit assumed an exit node's light per-connection cost; a relay now defaults to 256 concurrent connections, and a new `-max-conns` flag overrides the limit for any role.
- **Multi-second freeze recovering from a brief server reset.** When a session was dropped (server EOF/RST), the client's connectivity wait used a fixed 5 s ticker, so even a sub-second server blip quantized into a hard ~5 s stall with the data plane dead the whole time. Recovery now uses fast backoff (250 ms → 2.5 s) instead of a flat 5 s wait, the connectivity check returns as soon as TCP reachability is confirmed instead of blocking on parallel UDP/ICMP probes, and the blocking pre-flight check is skipped on the hot reconnect path (only re-armed after repeated connect failures). Typical recovery from a short reset drops from ~5 s to under 1 s.

## [1.3.15] - 2026-06-29

### Fixed

- **Reconnect storm on long-but-dying sessions.** The storm detector only parked a strategy after a streak of *short* sessions (under 20s). A meek/HTTP-polling tunnel that connects fine but is torn down at ~30s read past that threshold, so every session looked "healthy", the streak reset, and the client reconnect-stormed forever on a transport that could not hold a tunnel (observed as ~21 minutes of 30s reconnect cycles on a relayed chain). Added a frequency criterion: a strategy that reconnects 4 times within 3 minutes is parked regardless of individual session length, so the client falls through to a working strategy instead of looping.
- **Meek HTTP-polling sessions torn down on a slow keepalive echo.** The shared TUN relay tears a session down if no framed packet arrives within its 30s read timeout - correct for persistent transports, wrong for meek, whose liveness is the poll round-trip rather than tunnel payload. On an idle or degraded channel the server's keepalive echo could take more than one poll round-trip to return, killing an otherwise healthy polling session. A keepalive feeder now injects a synthetic frame off poll liveness (only at a frame boundary, so it cannot corrupt a packet); the relay stays up exactly as long as the poll layer is alive and times out promptly once polls genuinely stop.
- **Fast-reconnect loop guard.** `connectWithRTT` re-used the last successful strategy on a fast path while it was not parked, letting a strategy that connects but whose tunnel dies seconds later loop without ever being parked. More than 3 fast reconnects of one strategy within 5 minutes now forces a full strategy scan. The relay-mode `ConnectForReconnect` path, which retried a strategy up to 5 times with no parking check, now skips a storming (parked) strategy straight to the full scan.

## [1.3.14] - 2026-06-28

### Added

- **Auto-MTU active probe.** Tunnels now discover the largest packet size that actually traverses the path instead of relying on a hand-set `-tun-mtu`. After the TUN handshake the client sends echo probe frames through the data channel itself and the exit reflects same-size replies; the client searches for the ceiling (anchor 1280 -> optimistic jump to the configured cap -> binary search, with retries to distinguish packet loss from an MTU drop) and applies `min(probed, cap)` to the interface via a live MTU update. This measures the real path including relay framing, so relayed chains get their true MTU without per-node tuning. Capability is negotiated (handshake version `0x03` + server flag); peers that do not support it fall back to the existing static MTU negotiation. New `-auto-mtu` flag (default on); `-tun-mtu` becomes the upper bound. Exposes `tiredvpn_local_mtu_probed` and related probe metrics. Android live-raise (VpnService re-establish) is a follow-up; the full probe runs on standalone Linux/macOS today.

## [1.3.13] - 2026-06-27

### Fixed

- **Relay multi-hop MTU blackhole.** On relayed chains (client -> relay -> exit) the relay's upstream leg splits each TUN frame across multiple stego frames, but the exit's H2 TUN receiver expected a whole frame per stego payload and silently dropped anything larger. This capped the effective relay MTU around 996 bytes while direct tunnels carried the full 1400, so large packets over relayed chains were lost (visible as a PMTU blackhole). The exit now reassembles fragmented frames (bounded 128 KiB buffer, resync on malformed length, keepalives preserved), so relayed tunnels carry the full negotiated MTU. The reverse direction was already correct.

### Removed

- Dead buffer-pool helpers in `internal/server/bufpool.go`.

## [1.3.12] - 2026-06-27

### Security

- **Fixed a remote denial of service in ClientHello parsing.** `ExtractSNI` (and `RemoveREALITYExtension`) read into the handshake buffer without bounds checks, so a malformed, short ClientHello sent by any client could panic the server with an index-out-of-range and take down every connection. Both functions now bounds-check before each access, matching the existing safe parser.
- **Stopped logging client secrets and auth tokens at debug level.** Several debug log lines printed a prefix of the client secret and the raw auth token; these were removed so credentials no longer end up in logs.
- **Removed a `panic` from the packet data path.** The Morph padding path called `panic` if `crypto/rand` ever failed mid-stream, which would crash the whole server; it now uses a non-crypto source for padding (the wire format is unchanged) so a transient RNG error can't kill the process.
- **Optional bearer-token authentication for the management API.** The `/clients`, `/stats` and `/health` API had no authentication - safe only on loopback, but a misconfigured `-api-addr 0.0.0.0` exposed unauthenticated client management. A new `-api-token` (or `TIREDVPN_API_TOKEN`) enables `Authorization: Bearer` checking (constant-time comparison); when unset, behavior is unchanged and a warning is logged if the API binds to a non-loopback address. The admin CLI sends the token automatically.

### Removed

- **Dead-code cleanup.** Removed unreachable packages (`internal/proxy`, `internal/tunnel`, `internal/multiport`, the legacy JSON `internal/config/config.go`), unused structures (fake-packet injector, QUIC crypto fragmenter, resilient/health-monitored connections), the pre-pooled client handlers superseded by the pooled ones, duplicate secret/clientID generators, and deprecated unused `serverAddr` fields - about 160 unreachable symbols. No behavior change.

## [1.3.11] - 2026-06-26

### Fixed

- **Idle clients on the HTTP/2-stego strategy no longer reconnect every 30 seconds.** A client with no traffic sends a zero-length keepalive every 10 s and relies on the server echoing it back to reset its 30 s read deadline. Every TUN handler echoed a zero-length keepalive except the HTTP/2-stego one, which silently dropped it - so an idle HTTP/2-stego client received nothing for 30 s, hit its read-deadline, and did a (fast) reconnect. Over a long-RTT or relayed path this caused a brief blip on the first request after a pause and could break a transfer that ran longer than the idle window. The HTTP/2-stego handler now echoes the keepalive like the others.
- **ICMP tunnel key derivation now uses HKDF** instead of an ad-hoc construction, matching the rest of the codebase. Wire-compatible change deployed to both client and server together.

### Changed

- **More hot-path performance work on the strategies** (continuing the perf audit, each verified with `go test -race` and the linter):
  - REALITY reads are now buffered (`bufio`) and use a bounded per-connection decode buffer, instead of reading straight from the socket and retaining a full 16 KB buffer for a few leftover bytes.
  - Client TCP socket buffers raised from 64 KB to 4 MB to match the bandwidth-delay product on high-RTT links (the server upstream was already at 4 MB), so a single connection no longer caps throughput on long-latency paths.
  - A shared TLS client session cache across the TLS strategies enables session resumption, avoiding a full handshake on every reconnect.
- **Flaky timing tests stabilized.** Several tests relied on `time.Sleep` and runner-speed-dependent throughput assertions and intermittently failed in CI; they were rewritten to be deterministic, and the CI skip-list for them was removed so they actually run.

## [1.3.10] - 2026-06-26

### Changed

- **Hot-path performance pass across the transport strategies** (from an internal perf audit, each change verified with `go test -race` and the linter):
  - REALITY (the primary data path): encrypt in place with `XORKeyStream` into a single pooled buffer instead of a separate allocation plus two copies per chunk.
  - Morph: replaced a global RNG mutex with per-goroutine `math/rand/v2`, removing a lock that serialized the whole Morph data plane under concurrent connections.
  - Geneva: use the correct TLS-extension SNI walker (shared with REALITY) instead of a naive `00 00` scan that false-matched inside `key_share`.
  - HTTP polling: replaced a 10 ms busy-wait loop with a condition variable and made `SetReadDeadline` actually take effect.
  - WebSocket padding: build frames in one correctly sized buffer with an unrolled XOR mask and a non-cryptographic mask source.
  - State exhaustion: reuse a single packet buffer instead of 6+ allocations per decoy (byte-identical output verified).
  - HTTP/2 stego: use the standard library hex encoder and drop a dead code path.
  - Probe paths (confusion / anti-probe / SSH camouflage): a lightweight TCP-connect probe instead of a full TLS handshake (less load on server admission control), and they now resolve the same address as Connect (`GetServerAddr`, IPv6-aware).

### Fixed

- **Data race in the mesh strategy.** `relay.Available` was written without holding the lock that readers use; the relay-failure path also recursed instead of looping. Both fixed.

## [1.3.9] - 2026-06-26

### Fixed

- **`apt install tiredvpn` now works on amd64 again.** The APT repository was being published with only the last architecture processed - the amd64 package was missing from the index entirely (`binary-amd64/Packages` was empty), so `apt-get install tiredvpn` failed with "Unable to locate package tiredvpn" on amd64 hosts while arm64 worked. The cause was in the repository publish step: `reprepro removefilter` was scoped only by package and version, so when the loop processed the arm64 `.deb` it removed the amd64 entry of the same version that had just been added (and vice versa), leaving the repo with a single architecture. The filter is now scoped by architecture as well, so each `.deb` only replaces its own arch. (Fixes #45.)

## [1.3.8] - 2026-06-26

### Fixed

- **Relay mode (`-upstream`) now actually forwards client traffic to the upstream server.** In TUN mode the relay never invoked the upstream dialer - `handleTUNModeCore` had no upstream branch, so it always wrote client packets into its own local TUN device instead of proxying them onward, and no connection to the upstream was ever opened. On top of that, the upstream dialer never sent the `TypeStego` dispatch byte before the steganography handshake, so even the address-proxy path failed to authenticate against the upstream (the upstream saw a new connection but never authenticated it). The relay now opens a steganography tunnel to the upstream, performs the TUN handshake, forwards the upstream-assigned IP to the client, and transparently relays raw packet frames in both directions. A relay chain (client → relay → upstream → exit) now works end to end. Requires both the relay and the upstream server to run this version.

## [1.3.7] - 2026-06-25

### Fixed

- **The server no longer runs out of memory under a reconnect storm.** With no admission control, every accepted connection unconditionally spawned a handler goroutine, each holding a peek buffer and a 30 s read deadline; under a flood of probe/reconnect attempts (common under DPI pressure) goroutines piled up without bound and the process ballooned to gigabytes of RSS until the kernel OOM-killed it. Incoming connections are now bounded by a semaphore (`-max-conns`, default 4096): once the limit is reached, new connections are dropped and closed immediately rather than queued, so a storm sheds instead of accumulating, while legitimate clients keep being served. The initial read deadline for unclassified connections was also lowered from 30 s to 5 s so probe connections release their buffers quickly; the full fragmented-handshake deadline still applies once a connection is recognized.

## [1.3.6] - 2026-06-25

### Added

- **kTLS kernel module is auto-loaded on startup.** When kernel TLS offload is supported but the `tls` module isn't loaded, the process now tries to `modprobe tls` once at startup (5 s timeout) and enables offload if it succeeds. If it can't (no root, no modprobe), it logs a clear message and falls back to userspace crypto without blocking startup. For a permanent fix the log hints at adding `tls` to `/etc/modules-load.d/`.

### Fixed

- **The client no longer takes the whole machine offline when the server is unreachable.** It used to bring up the TUN device and install the default route (`0.0.0.0/0`) before the tunnel was connected, so with no connectivity to the server all traffic was black-holed into a dead interface - the host lost the network entirely and sat in a `waiting for network...` loop. Routes are now installed only after a successful connect and handshake; until then host routing is left intact and the client retries in the background.
- **TUN mode now works over the REALITY-mux transport.** The server reassigned a pool IP on every reconnect (ignoring `-tun-ip` and changing the address mid-session), so the interface address stopped matching the tunnel session and packets were dropped, while each reconnect tore down the policy route. IP allocation is now sticky per client: the same client gets the same address across reconnects (remembered in memory and Redis), and the client skips the address swap when the IP is unchanged, so routes stop flapping.
- **QUIC no longer pegs a CPU at 100%.** A failing QUIC accept loop spun without any backoff, retrying instantly forever and burning a full core whenever the listener returned a persistent error. The loop now backs off exponentially (10 ms up to 5 s, reset on a successful accept, interruptible on shutdown) and logs once if it stays degraded. TCP serving is unaffected.
- **Route installation is idempotent.** Adding a route that already existed failed with `file exists` and spammed warnings on every reconnect; route adds now use replace semantics.
- **`tiredvpn -version` no longer segfaults.** The flag is handled at the very start of `main`, before any initialization.
- **The IP pool no longer leaks addresses.** Dynamic (auto-assigned) leases now always carry a finite TTL so the background cleanup can reclaim them when a client disappears without a clean disconnect; sticky leases still survive reconnects within the TTL. A requested IP already held by another client is logged explicitly and falls back to a distinct address (never double-allocated), and out-of-network requested IPs are handled explicitly instead of silently.

## [1.3.5] - 2026-06-25

### Fixed

- **Throughput on long-haul links no longer collapses to ~3 Mbps.** The HTTP/2-stego transport advertised the default flow-control window of 65535 bytes, which caps a single stream at roughly one window per round trip - about 3.4 Mbps at 150 ms RTT, regardless of how much bandwidth the path actually has. On a relayed RU->AMS->USA chain where the underlying links sustain 70-90 Mbps, real throughput sat at ~3 Mbps. The initial window is now raised to 4 MB via `SETTINGS_INITIAL_WINDOW_SIZE`, and WINDOW_UPDATE frames are flushed proactively (256 KB threshold) instead of only on the next `Write`, which previously stalled the download direction where the receiver rarely writes. TCP socket buffers on the server and upstream legs were lifted from 64 KB to 4 MB to match the bandwidth-delay product. Measured end to end through the double tunnel, download went from 3 to 11 Mbps. The full gain needs both server and client updated, since the download rate is bounded by the receiver's advertised window.

## [1.3.4] - 2026-06-24

### Added

- **One-line installer and native packages.** `curl -fsSL https://tiredvpn.github.io/tiredvpn/install.sh | sudo bash -s -- --port 443` sets up a server end to end - generates a secret and self-signed cert, starts the service, and prints a `tired://` connection string plus a QR code. Native `.deb`/`.rpm` packages (amd64/arm64) are published to a signed apt/yum repository on GitHub Pages, so `apt install tiredvpn` / `dnf install tiredvpn` work. The package ships a systemd unit in a disabled state; `tiredvpn-init` finishes setup. CI builds and signs the packages and pushes the repo on every release.
- **Server TUN mode in containers.** A new `tun` Docker target (alpine + iptables) whose entrypoint auto-configures `ip_forward` and NAT from `-ip-pool`, a `docker compose --profile tun` service, and a Helm `server.tun.enabled` path (mounts `/dev/net/tun`, NET_ADMIN, hostNetwork). Previously a TUN server never came up in a container.

### Fixed

- **The fake website now convincingly mimics nginx.** It answered probes with an LF-delimited stub (no `Date`, no `Content-Length`, truncated body) that any scanner could tell apart from nginx instantly. It now replies like a stock nginx: CRLF headers in nginx order, live `Date`, real `Content-Length`, `Last-Modified`, an `ETag` in nginx's `hex-hex` form, `Accept-Ranges`, the byte-exact nginx default page (or files from `-fake-root`), HEAD without a body, and keep-alive.
- **`TIREDVPN_SECRET` is now actually read.** The server's error message promised it but the code only took `-secret` from the flag. The secret now falls back to the env var, so a systemd unit can pass it via `EnvironmentFile` instead of the command line.
- **Server `tiredvpn_info` metric reports the real version** instead of a hardcoded `0.2.0`.
- **Documentation audit:** corrected metric names (the monitoring doc listed metrics that don't exist), `-quic-port` default (443 -> 8443), admin flags, the new server `-tun-mtu`/`-config`, the registered Geneva strategy IDs, and the security reporting policy.

## [1.3.3] - 2026-06-23

### Added

- **Configurable server TUN MTU via `-tun-mtu`, lifting the 1280 ceiling.** The client already had `-tun-mtu`, but the server hardcoded its TUN interface and the MTU negotiation to `tun.DefaultMTU` (1280), so `effectiveMTU = min(clientMTU, 1280)` capped every tunnel at 1280 regardless of the client. The server now takes `-tun-mtu` (default 1280) and feeds it to both the shared TUN interface and the per-connection negotiation, so MTU > 1280 works end-to-end when both ends opt in. Both sides validate the range 1280-9000. Default 1280 keeps behavior identical to 1.3.2.

  Measured on an isolated test stand (REALITY tunnel, 100 MB download): ~2.33 MB/s at MTU 1500 vs ~1.78 MB/s at 1280 — roughly +30% download throughput from the larger MSS.

## [1.3.2] - 2026-06-23

### Fixed

- **JNI bridge mangled client arguments with spaces.** The Android entry point joined argv into a single space-separated string and the core split it back with `strings.Fields()`, so any value containing a space was torn apart — notably the canonical morph strategy IDs (e.g. `morph_Yandex Video`), which only survived via a fragile space-free-prefix workaround. `startClient` now takes a real string array (`jobjectArray`, decoded element by element) and the app passes argv as an array, so quoted/space-bearing flags (`-tun-routes`, secrets, morph IDs) arrive intact.
- **Android TUN throughput was throttled by an MTU mismatch.** The VpnService interface came up at MTU 1400 while the core framed packets and clamped TCP MSS against its own 1500 TUN MTU, so outer packets exceeded the real path MTU and hit fragmentation / PMTUD black-holing (worse on download). The interface and the core now default to MTU 1280 (the IPv6 minimum) so framing and clamping agree.

## [1.3.1] - 2026-06-22

### Fixed

- **REALITY reconnect storm that flapped the tunnel every ~1.6s.** `REALITYStrategy` kept a single `muxSess`/`muxConn` on the strategy object and closed it at the start of every `Connect` — a leftover of the intentionally-disabled smux reuse. Because the strategy is shared across the TUN tunnel, the proxy pool and the health checker, any second caller's dial silently tore down the live tunnel's TCP. Sessions died within seconds, the storm detector then parked REALITY for 5 minutes and failed traffic over to far slower polling strategies, which in turn spammed reconnects and tripped the circuit breaker (UDP through the tunnel stopped passing entirely). Each `Connect` now returns a self-contained connection that owns its own TCP, framing and smux session; closing one caller's connection can no longer disturb another's.
- **Storm detector parked the best strategy on startup turbulence.** A 30-second grace window after start and after every network change now ignores the short-lived sessions that legitimately occur while a tunnel settles (handshakes, route setup, transport warm-up), so a genuine storm still parks a strategy but normal churn does not.
- **`reconnects_total` and `connections_total` were always zero in TUN mode.** `IncReconnect` had no callers and `IncConnections` only ran in proxy mode, so the Prometheus counters were blind to reconnects. The TUN client now keeps atomic lifecycle counters and the existing metrics syncer forwards them, also refreshing `last_connect_timestamp`.

### Removed

- **Hetzner SNIs from the REALITY cover pool.** `hetzner.com` and `hetzner.cloud` are no longer used as cover destinations — fronting a Hetzner-hosted server with a Hetzner SNI is a needless correlation for a DPI. The `github.com` family remains as the cover pool.

## [1.2.2] - 2026-06-16

### Fixed

- **Proxy mode was unusable on the embedded/JNI client.** `parseClientArgs` defaulted `TunMode = true` and did not recognize `-listen`, so an embedded client started in proxy mode (no `-tun`, just `-listen`) was forced into TUN setup with no tun-fd and never came up. TUN is now opt-in via `-tun` (which the app's TUN path always passes), and `-listen` / `-http-listen` are parsed into `client.Config`.

## [1.2.1] - 2026-06-16

### Fixed

- **Embedded/JNI client dropped most flags.** `parseClientArgs` (the Android/host-managed entry point in `cmd/tiredvpn/jni_android.go`) was a hand-rolled switch that recognized only ~11 flags and had no default case, so every other flag was silently ignored. Embedded clients (the Android app) passing `-quic`, `-quic-port`, `-rtt-masking`, `-rtt-profile`, `-fallback`, and `-cover` got none of them - those features were dead on mobile. The parser also expected `-cover-host` while the CLI and the app send `-cover`, so the cover host was a guaranteed no-op.
- The parser now honors the full client flag contract (`-quic`, `-quic-port`, `-quic-sni-frag`, `-rtt-masking`, `-rtt-profile`, `-fallback`, `-shaper`, `-shaper-seed`, `-ech`, `-ech-config`, `-ech-public-name`, `-server-v6`, `-prefer-ipv6`, `-fallback-v4`), parsing into the same `client.Config` fields as the CLI path. The Traffic Shaper is built via the same `applyShaperFlag` helper as `runClient`, so embedded and CLI cannot drift. `-cover` is now canonical with `-cover-host` kept as an alias, and unknown flags are logged with `log.Warn` instead of dropped silently.

## [1.1.4] - 2026-06-02

### Added

- **macOS client (NEPacketTunnelProvider)** — the Go core can now run inside a host-managed macOS Network Extension. Adds a `MacOSMode` that, like `AndroidMode`, disables raw-socket/ICMP strategies and host-side route/DNS setup (the host owns the TUN fd, routes, and firewall); a CGo c-archive bridge (`cmd/tiredvpn/cgo_darwin.go`) exposing start/stop with state and log callbacks for the Swift app; a Darwin `utun` device (`internal/tun/tun_darwin.go`); and Makefile targets `build-macos-cli` and `build-macos-lib` (universal arm64+amd64 `libtiredvpn.a`). The `jni_context.go` host-context entrypoint now builds for `darwin` as well as `android`.

### Fixed

- **`admin add` / `admin list` / `admin delete` targeted a non-existent API** — the admin subcommands talked to `/api/clients`, which the server does not route, so every call returned 404. `admin add` also posted `{id, secret}`, but the create endpoint takes `{name}` and generates the id (UUID) and secret server-side. Repointed all three commands to `/clients` and `/clients/{id}`; `add` now sends `name` (plus optional `tun_ip`, `max_conns`, `expires_in`) and reads the server-issued id and secret from the response to build the connection string; `list` decodes the `{clients:[...]}` envelope instead of a bare array. The `-id`/`-secret` flags on `add` are replaced by a required `-name`.

### Changed

- **kTLS upgrade is now performed per-handler at the relay-phase boundary** instead of unconditionally after the TLS handshake. `tired-raw` and `tired-confusion` handlers now call `ktls.TryEnable` after their auth-complete ack write, before the relay goroutines spin up. `tired-morph`, `tired-stego`, `tired-ws`, and `tired-polling` continue to run without kTLS pending Phase 2 (handler-level framer/upgrade rework). Behaviour-equivalent for end users; eliminates the EBADMSG race that the static `kTLSUnsafe` exclusion list was a workaround for. Also adds `ClientRegistry.SwapConn` so registry-tracked handlers can update the stored connection pointer after the kTLS swap, keeping forced-disconnect `Close()` targeting the live socket wrapper instead of the stale `*tls.Conn`. Includes an in-process e2e regression test (`TestRawTunnelKTLSHandover`) that catches future regressions where a TLS-stack read is reintroduced after `TryEnable`.
- **kTLS Phase 2 — `tired-stego`, `tired-morph`, `tired-ws` migrated onto per-handler kTLS.** `tired-stego` now reads the HTTP/2 preface manually (`readH2Preface`), upgrades to kTLS, then builds the framer over the post-Enable conn (`newH2Framer`). `tired-ws` server- and client-side replace `bufio.Reader` parsing with byte-exact `readHTTPRequestExact` / `readWSUpgradeResponseExact` so the upgrade headers do not over-read past `\r\n\r\n` into bytes the kernel TLS counter has already advanced past. **`tired-morph` is a hard cutover**: the wire protocol gains a 1-byte server-to-client ack written immediately after auth verification (early-ack design); old morph clients that don't read this byte will desync — coordinate the deploy. The `kTLSUnsafe` exclusion symbol is now gone entirely; `TestKTLSUnsafeMapRemoved` codifies the invariant. `tired-polling` stays without kTLS — every poll opens a fresh TCP connection (`Connection: close`), so the relay-phase amortization that makes kTLS worthwhile does not apply; documented in the design spec.

## [1.1.3] - 2026-05-06

### Fixed

- **HTTP/2 Steganography and WebSocket Salamander on kTLS-capable hosts** — disabled kTLS for `tired-stego` and `tired-ws` ALPN connections. Both protocols send application data immediately after the TLS handshake; the Go TLS stack may buffer the first record before `ktls.Enable()` is called, causing the kernel's AEAD sequence counter to be out of sync and failing decryption with `EBADMSG`. Consistent with the existing exclusion of `tired-morph` and `tired-polling`.

## [1.1.2] - 2026-05-06

### Fixed

- **Traffic Morph strategies** (Yandex, VK, Baidu, Aparat Video) — increased TLS ClientHello fragment size from 2 bytes to 64 bytes, reducing TCP segment count from ~750 to ~24. The extreme fragmentation caused reliable timeouts on high-latency paths where the last segments of a 1500-byte ClientHello were dropped.
- **Server TLS reassembly timeout** — replaced per-chunk 5-second deadline with a single 30-second connection deadline, preventing premature timeout on fragmented TLS records.
- **Benchmark probe timeout** — increased per-strategy probe timeout from 10 s to 30 s to accommodate slow paths.

## [1.1.1] - 2026-05-05

### Added

- **`-benchmark-json` flag** — machine-readable JSON output for all bypass strategies (`available`, `blocked`, `timeout`, `latency_ms`, `fastest`). Powers the daily availability reports published to `reports/`.

### Fixed

- `context canceled` errors now correctly classified as `timeout` (not `blocked`) in benchmark output.
- Zero-latency strategies (`latency_ms = 0`) now included in JSON output.
- Debug strategy summary redirected to stderr to avoid corrupting JSON stdout.
- `ldflags` version correctly propagated into client package before `Run()`.

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
