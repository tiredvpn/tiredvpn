# kTLS Phase 2 — Design Spec

**Date:** 2026-05-06
**Author:** project owner (in collaboration with brainstorming session)
**beads:** `tiredvpn-oss-u7c`
**Branch:** `task/ktls-phase-2`
**Predecessor:** Phase 1 (PR #31, branch `task/ktls-relay-phase`) — `tired-raw` + `tired-confusion` got per-handler kTLS at the relay-phase boundary.

## Goal

Extend the per-handler kTLS-at-relay-phase pattern from Phase 1 to the four remaining ALPN protocols still in the `kTLSUnsafe` exclusion list: `tired-morph`, `tired-stego`, `tired-ws`, `tired-polling`. End state: the `kTLSUnsafe` map and its consumer logic are removed entirely; every `tired-*` handler is responsible for upgrading the connection at its own auth-complete boundary.

## Scope

**In scope:**
- `tired-morph` — server `handleMorphConnection` + client `internal/strategy/morph.go`. Hard cutover with explicit 1-byte ack (no v1 backward compatibility — old clients are expected to upgrade alongside the server).
- `tired-stego` — server `handleHTTP2WithALPN` (refactor `initH2Framer` to split preface read from framer creation). Client side already correct (post-handshake Enable in `internal/strategy/stego.go`); not modified.
- `tired-ws` — server `handleWebSocketPadded` (replace `bufio.Reader` parser with byte-exact reader) + client `internal/strategy/ws.go` (mirror change).
- `tired-polling` — server `handleHTTPPollingWithALPN` (lift off `net/http` to hand-rolled HTTP/1.1 framer over `conn`) + client `internal/strategy/polling.go` (corresponding refactor). **Pre-check on plan stage:** if the existing protocol does not use HTTP keep-alive, polling is deferred (kTLS only pays off across multiple requests on the same TCP connection).
- Removal of the `kTLSUnsafe` exclusion logic from `handleConnection`.
- `ClientRegistry.SwapConn` integration in any handler that calls `AddConnection` and now also calls `TryEnable` (`handleMorphConnection`, `handleWebSocketPadded` already register; verify and apply pattern from Phase 1).
- Test additions: e2e test for `tired-morph` (new ack protocol); unit tests for the new `readH2Preface`, `readHTTPRequestExact` (used by ws and polling), and a final assertion test that `kTLSUnsafe` is no longer present in `server.go`.

**Out of scope:**
- Backward compatibility for `tired-morph` — hard cutover chosen during brainstorming. Old clients are expected to break until they update.
- New ALPN identifiers; all four ALPN strings remain unchanged.
- Profiling / telemetry beyond the existing first-activation `log.Info` from Phase 1.
- TUN-mode-specific paths in `handleConfusionTUNMode` and `handleMorphTUNMode` already covered by the Phase 1 / current refactor; no new TUN logic.

## Architecture

The Phase 1 contract stands: `internal/server/server.go:handleConnection` performs only TLS handshake + ALPN routing; it does NOT call `ktls.Enable`. Each per-protocol handler is responsible for invoking `ktls.TryEnable(conn, label)` at the exact point where (a) all protocol-level auth/header bytes have been drained from the TLS stack and (b) only byte-relay (or symmetric request/response over the same socket) remains.

Phase 2 only adds new handler-level call sites; it does not change `handleConnection`, the helper `ktls.TryEnable`, or the `ClientRegistry.SwapConn` API.

## Per-protocol design

### tired-morph (hard cutover, server + client)

**Wire format change:** server writes a 1-byte ack (`0x00` success / `0x01` fail) immediately after authentication and target-dial succeed (or fail). Client must read the ack before sending application data.

**Server flow** (`internal/server/server.go:handleMorphConnection`, line ~1280):
1. Read `MRPH(4) + nameLen(1) + name + auth(32)`.
2. Verify auth against per-client and global secrets — same as today.
3. Read first morph packet header + body (contains target address). Same as today.
4. Dial the target.
5. Write ack: `0x00` on success, `0x01` on dial failure. **(new)**
6. `conn = ktls.TryEnable(conn, "tired-morph")`. **(new)**
7. If registry-tracked, call `srvCtx.registry.SwapConn(clientID, preSwap, conn)` with the pre-swap reference. **(new — same pattern as `handleRawTunnel`)**
8. Anonymous-defer wrapping `RemoveConnection` (so closure picks up post-swap conn) — same pattern as Phase 1.
9. Run relay goroutines.

**Client flow** (`internal/strategy/morph.go`):
1. After TLS handshake (existing), build morph handshake bytes: `MRPH + nameLen + name + auth + first morph packet`.
2. Write the handshake bytes through `*tls.Conn` (existing).
3. **(new)** `io.ReadFull(tlsConn, ack[:1])` with a 5s deadline. On error or `ack[0] == 0x01`, close and return error.
4. **(new)** `conn = ktls.TryEnable(tlsConn, "tired-morph")` after successful ack.
5. Wrap with `MorphedConn` over the post-Enable conn (existing wrapping flow keeps working — `MorphedConn` is `net.Conn`-typed).
6. Existing kTLS Enable in `morph.go` line ~335 (which currently happens after TLS handshake but before `MorphedConn`) is **moved** to after the ack read.

**`kTLSUnsafe` change:** remove `"tired-morph": true` entry.

### tired-stego (server-side refactor, client unchanged)

**Refactor `initH2Framer` into two helpers:**

```go
// readH2Preface reads and validates the 24-byte HTTP/2 client preface
// from conn through the live TLS stack. Must be called before kTLS Enable
// on the server side, since the preface bytes may be sitting in the TLS
// stack's read buffer after handshake.
func readH2Preface(conn net.Conn, logger *log.Logger) error

// newH2Framer constructs the HTTP/2 framer over conn and writes the
// initial server SETTINGS frame. Safe to call after kTLS Enable —
// framer holds a permanent reference to conn for subsequent frame I/O.
func newH2Framer(conn net.Conn, logger *log.Logger) (*http2.Framer, error)
```

**Server flow** (`handleHTTP2WithALPN`, line ~1032):
```go
func handleHTTP2WithALPN(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
    if err := readH2Preface(conn, logger); err != nil {
        return
    }
    conn = ktls.TryEnable(conn, "tired-stego")
    framer, err := newH2Framer(conn, logger)
    if err != nil {
        return
    }
    runH2FrameLoop(conn, framer, /* ... */)
}
```

**Legacy `handleHTTP2`** (called from `handleTLSConnectionLegacy` for non-ALPN clients) keeps using the original `initH2Framer` (which combines preface read + framer build) — no kTLS for legacy path. Phase 2 does NOT touch `handleHTTP2` or the legacy fallback.

**Client unchanged:** `internal/strategy/stego.go` already calls `ktls.Enable` after `tlsConn.HandshakeContext` — race-free for client-first protocols.

**`kTLSUnsafe` change:** remove `"tired-stego": true` entry.

### tired-ws (server-side refactor, client mirror)

**Replace `bufio.Reader` parser with `readHTTPRequestExact`:**

```go
// readHTTPRequestExact reads an HTTP/1.1 request line + headers from conn
// strictly up to and including the empty-line terminator (\r\n\r\n) and
// not one byte further. Implementation reads ONE byte at a time via
// io.ReadFull(conn, buf[:1]) and tracks a 4-byte sliding suffix; returns
// when the suffix matches \r\n\r\n. This is byte-exact: by construction
// no Read() consumes more bytes than the terminator, so a subsequent
// conn.Read() (potentially after kTLS Enable) starts on the first
// post-terminator byte (request body, next protocol frame, etc.).
//
// Caps total bytes read at maxHeaderBytes (default 8192) to defend
// against DoS; returns an error if the cap is hit before the terminator.
//
// Performance: ~500 syscalls for a typical 500-byte request. On loopback
// or kTLS-enabled paths this is on the order of microseconds and is
// dwarfed by the TLS handshake cost; we accept the cost as the price
// of byte-exact parsing for kTLS safety.
func readHTTPRequestExact(conn net.Conn, maxHeaderBytes int) (
    requestLine string,
    headers map[string]string,
    err error,
)
```

The function reads through `conn.Read()` in small increments (e.g. 64-byte chunks) and stops as soon as `\r\n\r\n` is observed. It **never** over-reads past the empty-line terminator, so the next `conn.Read()` (after kTLS Enable) starts on the first WebSocket frame byte.

**Server flow** (`handleWebSocketPadded`, line ~3229):
1. Replace `bufio.NewReader(conn)` with `readHTTPRequestExact(conn, 8192)`. Validate `Sec-WebSocket-Key`, `X-Salamander-Version`, `X-Auth-Token` from the returned headers map.
2. Auth flow unchanged.
3. Write `Sec-WebSocket-Accept` upgrade response (existing code).
4. **(new)** `conn = ktls.TryEnable(conn, "tired-ws")`.
5. **(new)** SwapConn if registry-tracked.
6. Anonymous-defer for RemoveConnection (Phase 1 pattern).
7. Parse WebSocket frames over the post-Enable conn (existing code, but reading through new conn).

**Client flow** (`internal/strategy/ws.go`):
1. After TLS handshake (existing), write upgrade request (existing).
2. **(new)** Use a symmetric `readHTTPResponseExact` (or local equivalent) to read the upgrade response without bufio over-read.
3. **(new)** `ktls.TryEnable` after upgrade response is received.
4. Existing WebSocket framing layer wraps the new conn.

**`kTLSUnsafe` change:** remove `"tired-ws": true` entry.

### tired-polling (server + client major refactor; **conditional on keep-alive precheck**)

**Pre-check (on plan stage, before writing implementation tasks):** read `internal/server/server.go:handleHTTPPollingWithALPN` and `internal/strategy/polling.go`. Determine:
1. Does the current implementation use HTTP keep-alive (multiple requests over a single TCP connection)?
2. Does it use `net/http` server / client, or a custom HTTP/1.1 implementation already?

**If keep-alive is used:**
- Lift the polling handler off `net/http` to a hand-rolled HTTP/1.1 framer using `readHTTPRequestExact` (shared with ws).
- After the first request/response cycle (auth-equivalent boundary): `conn = ktls.TryEnable(conn, "tired-polling")`.
- Subsequent poll cycles use the same framer over the kTLS conn.
- Client side: corresponding refactor.

**If keep-alive is NOT used (each poll = new TCP):**
- kTLS does not pay off (full TLS handshake per request, no relay phase).
- **Defer polling** to a future PR — leave `tired-polling` in the (otherwise empty) `kTLSUnsafe` map, document the gap in CHANGELOG, treat the empty-map invariant as "almost done".
- This contingency is the only reason the `kTLSUnsafe` map might survive Phase 2.

**`kTLSUnsafe` change:** remove `"tired-polling": true` only if keep-alive precheck passes. Otherwise, keep the entry (sole survivor) and document.

### Final invariant

If polling proceeds (keep-alive case): `kTLSUnsafe` map is removed entirely from `server.go` and `handleConnection` ALPN-routing has no exclusion table.

If polling is deferred (no-keep-alive case): `kTLSUnsafe = {"tired-polling": true}` survives. We add a regression test asserting that no other entries exist.

## Data flow diagrams (summary; full inline in design pass)

### morph

```
Client                                 Server
  ── TLS handshake (ALPN tired-morph) ─→
  ── MRPH+name+auth+first packet     ─→  verify, dial target
                                    ←──  ack 0x00 / 0x01
  read ack
  if 0x00:
    TryEnable(tlsConn)                    TryEnable(tlsConn)
    SwapConn (if client-tracked)          SwapConn(clientID, oldConn, newConn)
    relay through ktlsConn                relay through ktlsConn
  else:
    close, error
```

### stego

```
Client (unchanged)                     Server (refactored)
  TLS handshake ALPN=tired-stego  ──→  handleHTTP2WithALPN(tlsConn):
  ktls.TryEnable                          readH2Preface(tlsConn)        // drains TLS buffer
  Send H2 preface                  ──→   conn = ktls.TryEnable(tlsConn)
                                          framer = newH2Framer(conn)
                                          runH2FrameLoop(conn, framer, …)
```

### ws

```
Client                                 Server (refactored)
  TLS + Upgrade request bytes      ──→ readHTTPRequestExact(conn)
                                       validate headers + auth
                                ←─── 101 Switching Protocols + Sec-WebSocket-Accept
  read upgrade response (exact)
  TryEnable                              TryEnable
  WS frames                       <──→  WS frames over kTLS
```

### polling (keep-alive case)

```
Client                                 Server (refactored)
  TLS + first POST /poll          ──→  readHTTPRequestExact(conn)
                                       validate auth, write data response
  read response (exact)
  TryEnable                              TryEnable
  HTTP/1.1 POST /poll over kTLS  <──→  readHTTPRequestExact via ktls
  …                                     write response via ktls
```

## Error handling

Same posture as Phase 1:
- ack-write failures → `logger.Warn` (operationally significant, broken TCP after a successful upstream dial).
- preface / upgrade / first-poll-request read failures → `logger.Debug`, return.
- `ktls.TryEnable` returning `nil` (no kernel TLS support) → both sides continue through `*tls.Conn` transparently — Phase 1's `TryEnable` doc comment already covers this.
- Read deadlines on client-side ack/response reads (5s) to avoid hangs on stuck server.

## Migration / deployment

**Hard cutover for `tired-morph`:** server and client are protocol-incompatible across the version boundary. Both failure modes corrupt the relay:

- **Old client → new server.** Old client writes `MRPH+name+auth+first packet` then immediately starts streaming morph data without ever reading. New server reads the handshake, dials, writes `0x00` ack and continues. Old client's data stream is interleaved with the ack byte that it never expected to read; first read on the old client receives the byte `0x00` from the server's ack, treats it as the start of a morph response frame, framing desyncs, connection dies on the next length check.
- **New client → old server.** New client writes handshake then blocks reading 1 byte of ack. Old server reads handshake, dials, immediately starts relaying target data without writing an ack. New client reads the first byte of target data, treats it as ack — if it happens to be `0x00`, kTLS upgrades and the rest of the relay stream is shifted by 1 byte and corrupts on the next morph framing boundary; if non-zero, client treats as failure ack and closes.

Both modes silently corrupt rather than cleanly fail. There is no "graceful degradation" without an ALPN bump (option A in brainstorming), which was rejected.

**Mitigation outside the codebase:**
- Coordinate server and client deploys.
- Communicate breaking change to users on the day of the release.
- Old clients that haven't updated will fail to connect cleanly until they update; this is the explicit acceptance of the hard-cutover choice.

This is a deployment-process concern, not a code concern; the spec only records the constraint so a future contributor doesn't think they can ship the server side independently.

## Risks

1. **Polling keep-alive assumption may not hold.** Mitigation: precheck on plan stage; defer if needed.
2. **morph hard cutover breaks unupgraded clients.** Mitigation: documented; deployment plan handles this.
3. **`readHTTPRequestExact` performance.** Byte-by-byte reading is slower than `bufio`, but request size is ~500 bytes typical. Worst case (~8KB cap) is still <16ms over loopback. Negligible relative to TLS handshake cost.
4. **stego framer rebuild order.** Must call `ktls.TryEnable` strictly between preface read and framer construction, never the other way around. Plan should include a unit test that forces this ordering.
5. **WebSocket Sec-WebSocket-Key calculation hashes** — moving from `bufio` to `readHTTPRequestExact` changes the parser but not the hashing input. Existing handshake validation tests should keep passing.

## Test strategy

1. **`TestMorphKTLSHandover`** (new e2e): TLS listener + server-side morph handler in-process + client-side dial → write handshake → read ack → exchange payload → assert echo. Modeled on `TestRawTunnelKTLSHandover` from Phase 1 with the additional ack step.
2. **`TestReadH2Preface_*`** (unit): valid preface, truncated preface, garbage preface.
3. **`TestReadHTTPRequestExact_*`** (unit): valid request, request larger than max-header cap, malformed (no terminator), boundary case (terminator at exact buffer chunk boundary).
4. **`TestKTLSUnsafeMapRemoved`** (assertion): grep-style test that fails if the symbol `kTLSUnsafe` reappears in `server.go`. Or, equivalently, asserts that all `tired-*` ALPN values pass through `handleTLSConnection` without exclusion logic.
5. **Race detector** on touched packages (`internal/server`, `internal/strategy`, `internal/ktls`).

No e2e tests for stego / ws / polling at this stage — the kTLS handover mechanic is identical to morph and tired-raw (already tested), and adding three more in-process TLS harnesses inflates test surface without proportional regression-detection value. Documented as a follow-up if specific bugs surface.

## File-level changes (preview)

- `internal/server/server.go` — modify `handleMorphConnection`, `handleHTTP2WithALPN`, `handleWebSocketPadded`, `handleHTTPPollingWithALPN`, remove `kTLSUnsafe` map (conditionally for polling).
- `internal/server/h2_helpers.go` (new file or in `server.go`) — `readH2Preface`, `newH2Framer`.
- `internal/server/http_request_reader.go` (new file) — `readHTTPRequestExact`.
- `internal/strategy/morph.go` — move kTLS Enable to post-ack read; add ack-read step.
- `internal/strategy/ws.go` — symmetric readHTTPResponseExact + post-upgrade Enable.
- `internal/strategy/polling.go` — refactor (conditional).
- `internal/server/morph_ktls_test.go` (new) — `TestMorphKTLSHandover`.
- `internal/server/h2_helpers_test.go` (new) — `TestReadH2Preface_*`.
- `internal/server/http_request_reader_test.go` (new) — `TestReadHTTPRequestExact_*`.
- `internal/server/ktls_invariant_test.go` (new) — `TestKTLSUnsafeMapRemoved`.
- `CHANGELOG.md` — Unreleased entry.

## Out of this spec

- Implementation step-by-step task breakdown — done in the next phase via `superpowers:writing-plans`.
- Profiling-driven decisions on polling beyond the keep-alive precheck.
- Phase 3 (e.g. analogous e2e tests for tired-confusion, observability metrics) — separate spec if needed.
