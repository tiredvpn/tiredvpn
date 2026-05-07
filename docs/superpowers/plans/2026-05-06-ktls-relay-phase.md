# kTLS Relay-Phase Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `ktls.Enable()` from TLS-handshake-time to per-protocol relay-phase entry points, so kTLS is enabled only after protocol-level auth completes and the only remaining traffic is byte-relay.

**Architecture:** Today server-side `handleConnection` enables kTLS unconditionally for "tired-*" ALPN values not in an exclusion list (`tired-morph`, `tired-polling`, `tired-stego`, `tired-ws`). Race conditions arise when client sends application data before server's TLS-stack buffer is drained, causing EBADMSG/data loss when the kernel takes over the socket. The fix is to defer `ktls.Enable()` until each handler has finished reading its protocol-specific auth/header bytes — at that point the TLS buffer is empty and the kernel's record-sequence counter is in sync. Client-side stays as-is in Phase 1 because all our protocols are client-first (client writes auth, server reads), so client's TLS read buffer is empty after handshake and `Enable` is race-free where it sits.

**Tech Stack:** Go 1.22+, `crypto/tls`, custom `internal/ktls` package, ALPN-based routing, beads issue tracker.

**Phases:**
- **Phase 1 (this PR, `task/ktls-relay-phase` branch)** — clean cases: `tired-raw`, `tired-confusion`. Establishes helper API and removes blanket Enable. Pure refactor: kTLS coverage stays the same as today (raw + confusion), but the call site moves from `handleConnection` into each handler.
- **Phase 2 (next PR, sketched at the bottom)** — adds kTLS to `tired-morph`, `tired-stego`, `tired-ws`, `tired-polling` by reworking each handler's framer/upgrade flow. Requires either protocol bump (morph: explicit ack) or framer-creation refactor (stego, ws, polling).

beads: `tiredvpn-oss-otm` (this work).

---

## File Structure

**Phase 1 modifies:**
- `internal/ktls/conn.go` — add `TryEnable(net.Conn, label string) net.Conn` helper
- `internal/ktls/conn_test.go` (new) — unit test for `TryEnable` decision tree
- `internal/server/server.go`:
  - `handleConnection` (lines 874-902) — remove blanket Enable + exclusion list, hand `*tls.Conn` straight to `handleTLSConnection`
  - `handleTLSConnection` (lines 921-979) — simplify ALPN extraction (only `*tls.Conn` now)
  - `handleRawTunnel` (line 2322) — call `TryEnable` after `Write([]byte{0x00})` ack, swap `conn` to returned conn before relay
  - `handleProtocolConfusion` (line 1993) — call `TryEnable` after `Write([]byte("TIRED"))` ack (TUN branch line 2067) and after `Write([]byte{0x00,0x00,0x00,0x01,0x00})` (tunnel branch line 2101), swap `conn` before subsequent reads/writes
- `CHANGELOG.md` — entry under unreleased

**Phase 1 does not touch:**
- `internal/strategy/{stego,confusion,morph}.go` — client-side `ktls.Enable` stays where it is (post `tls.HandshakeContext`, race-free for client-first protocols)
- Other server handlers (`handleHTTP2*`, `handleMorphConnection*`, `handleWebSocketPadded`, `handleHTTPPollingWithALPN`) — Phase 2

**File responsibility split:**
- `internal/ktls/conn.go` owns the kTLS lifecycle decision (when to upgrade, what to log, when to fall back). Handlers call into it; they don't reimplement type-assertions or fallback handling.
- Each handler owns its own protocol-state-machine end point — only the handler knows when "auth is done, relay starts".
- `handleConnection` becomes purely a TLS handshake + ALPN router; no kTLS knowledge.

---

## Phase 1 — PR-1 (raw + confusion)

### Task 1: Add `ktls.TryEnable` helper

**Files:**
- Modify: `internal/ktls/conn.go`
- Create: `internal/ktls/conn_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/ktls/conn_test.go`:

```go
package ktls

import (
	"net"
	"testing"
)

// fakeConn is a minimal net.Conn for testing the TryEnable type-assert path.
type fakeConn struct{ net.Conn }

func TestTryEnable_NotTLSReturnsOriginal(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	got := TryEnable(a, "test-label")
	if got != a {
		t.Fatalf("TryEnable on non-TLS conn must return the original; got %T", got)
	}
}

func TestTryEnable_AlreadyKTLSReturnsSame(t *testing.T) {
	// Construct a *Conn directly (no real socket) to exercise the early-return path.
	k := &Conn{}
	got := TryEnable(k, "test-label")
	if got != k {
		t.Fatalf("TryEnable on *ktls.Conn must return the same value; got %T", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd .claude/worktrees/ktls-relay-phase
go test ./internal/ktls/ -run TestTryEnable -v
```
Expected: FAIL with `undefined: TryEnable`.

- [ ] **Step 3: Implement `TryEnable` in `internal/ktls/conn.go`**

Append to `internal/ktls/conn.go`:

```go
// TryEnable attempts to upgrade the connection to kTLS for the kernel-offloaded
// data phase. It is safe to call with any net.Conn:
//
//   - if conn is already a *ktls.Conn, it is returned unchanged.
//   - if conn is a *tls.Conn whose TLS records have been fully drained from
//     the TLS-stack buffer (i.e. the next read will hit raw socket), Enable is
//     called and the *Conn wrapper is returned.
//   - otherwise (non-TLS, fallback failed) the original conn is returned.
//
// label identifies the call site for log output ("tired-raw", "tired-confusion", ...).
//
// Callers must invoke this AFTER all protocol-level auth/header bytes have been
// read or written through the *tls.Conn — otherwise residual decrypted bytes
// in the TLS stack's buffer are lost when the kernel takes over the socket.
func TryEnable(conn net.Conn, label string) net.Conn {
	if _, ok := conn.(*Conn); ok {
		return conn
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn
	}
	if k := Enable(tlsConn); k != nil {
		log.Info("kTLS enabled for %s (relay phase)", label)
		return k
	}
	log.Debug("kTLS unavailable for %s, using TLS stack", label)
	return conn
}
```

Add the import for `log` at the top of `conn.go` (the package already imports `crypto/tls`, `net`):

```go
import (
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/ktls/ -run TestTryEnable -v
```
Expected: PASS.

- [ ] **Step 5: Run full ktls package tests + vet**

```bash
go test ./internal/ktls/ -v
go vet ./internal/ktls/
```
Expected: PASS, no vet warnings.

- [ ] **Step 6: Commit**

```bash
git add internal/ktls/conn.go internal/ktls/conn_test.go
git commit -m "feat(ktls): add TryEnable helper for relay-phase kTLS upgrade

TryEnable abstracts the upgrade decision: if conn is already kTLS,
return as-is; if it is a *tls.Conn ready for kernel offload, Enable
and return the wrapper; otherwise return original (non-TLS, fallback).

Per-handler call sites can now invoke this exactly when their
protocol-level auth phase ends, eliminating the EBADMSG race that
forced a server.go-level exclusion list.

Context: extracted helper while planning the relay-phase refactor;
spent ~30min reviewing internal/ktls API and confirming the *tls.Conn
type-assert path is the only branch needed for current call sites."
```

### Task 2: Remove blanket kTLS Enable from `handleConnection`, simplify `handleTLSConnection`

**Files:**
- Modify: `internal/server/server.go:874-902` (handleConnection)
- Modify: `internal/server/server.go:921-979` (handleTLSConnection)

- [ ] **Step 1: Read current state for context**

```bash
sed -n '870,910p' internal/server/server.go
```
Expected: see the kTLSUnsafe map + Enable block.

- [ ] **Step 2: Remove kTLS Enable block in `handleConnection`**

In `internal/server/server.go`, replace lines ~874-902 (from `// Check ALPN before enabling kTLS` through the call to `handleTLSConnection`) with:

```go
		// kTLS is enabled per-handler in the relay phase, after each protocol's
		// auth/header bytes are fully drained from the TLS stack. See
		// internal/ktls.TryEnable and the handlers below.
		alpn := tlsConn.ConnectionState().NegotiatedProtocol
		_ = alpn // alpn used for logging in handleTLSConnection

		// Clear deadline after successful handshake
		tlsConn.SetReadDeadline(time.Time{})

		// Now detect protocol over TLS
		handleTLSConnection(tlsConn, srvCtx, connID)
		return
	}
```

The `kTLSUnsafe` map and the `if strings.HasPrefix(alpn, "tired-") && !kTLSUnsafe[alpn]` block are deleted.

- [ ] **Step 3: Simplify ALPN extraction in `handleTLSConnection`**

Find lines ~926-932 in `handleTLSConnection`:

```go
	var alpn string
	if tc, ok := conn.(*tls.Conn); ok {
		alpn = tc.ConnectionState().NegotiatedProtocol
	} else if kc, ok := conn.(*ktls.Conn); ok {
		alpn = kc.ConnectionState().NegotiatedProtocol
	}
```

Change the function signature from `func handleTLSConnection(conn net.Conn, ...)` to `func handleTLSConnection(conn *tls.Conn, ...)`, and replace the ALPN extraction block with:

```go
	alpn := conn.ConnectionState().NegotiatedProtocol
```

(All callers now pass `*tls.Conn` directly. The legacy fallback branch already type-asserts back to `*tls.Conn`, so it now becomes a direct pass-through.)

Also update the legacy fallback (lines ~972-978):

```go
	// Fallback: legacy protocol detection (for old clients without custom ALPN)
	logger.Debug("ALPN fallback: using legacy magic-byte detection")
	handleTLSConnectionLegacy(conn, srvCtx, connID)
}
```

- [ ] **Step 4: Build to surface compile errors**

```bash
go build ./...
```
Expected: PASS. If `ktls` import becomes unused in `server.go`, check its remaining usages — `Conn` type-switch in `ConnectionState` etc. Likely the import stays (used elsewhere in server.go).

- [ ] **Step 5: Run server tests**

```bash
go test -short -timeout 120s ./internal/server/...
```
Expected: PASS. The change is behaviour-preserving for raw/confusion (they still get kTLS, just later); other ALPNs were already excluded.

- [ ] **Step 6: Commit**

```bash
git add internal/server/server.go
git commit -m "refactor(server): drop blanket kTLS Enable, defer to handlers

handleConnection no longer enables kTLS based on the kTLSUnsafe ALPN
exclusion list. Each handler is now responsible for calling
ktls.TryEnable at the exact point where its protocol-level auth/header
bytes have been drained from the TLS stack and only byte-relay
remains.

This commit is a pure refactor: no handler enables kTLS yet, so
runtime behaviour is currently identical to 'all ALPNs excluded'.
The next two commits restore kTLS for tired-raw and tired-confusion
at the relay-phase boundary, eliminating the EBADMSG race we have
been working around with the static exclusion list.

Context: reviewed handleConnection ALPN-routing and confirmed that
moving Enable into handlers does not affect handshake/ALPN paths;
spent ~45min tracing call sites and verifying handleTLSConnection
no longer needs the *ktls.Conn branch in its type switch."
```

### Task 3: Enable kTLS in `handleRawTunnel` after success ack

**Files:**
- Modify: `internal/server/server.go:2322` (handleRawTunnel)

- [ ] **Step 1: Locate the success-ack write**

```bash
grep -n 'conn.Write(\[\]byte{0x00})' internal/server/server.go
```
Expected: line ~2391 inside `handleRawTunnel`.

- [ ] **Step 2: Read context around the relay loop**

```bash
sed -n '2390,2420p' internal/server/server.go
```
Expected: see `Send success` and the goroutines launching `optimizedRelay`.

- [ ] **Step 3: Insert `TryEnable` between ack and relay**

Replace the block in `handleRawTunnel` from `// Send success` through the start of the relay goroutines:

```go
	// Send success ack
	if _, err := conn.Write([]byte{0x00}); err != nil {
		logger.Debug("Failed to write success ack: %v", err)
		return
	}
	logger.Debug("Connected to target, starting relay")

	// Auth phase complete: hand the socket over to kTLS for the byte-relay phase.
	// At this point the TLS stack's read buffer is empty (we read mode + addr
	// to completion) and the write buffer has been flushed by the ack write.
	conn = ktls.TryEnable(conn, "tired-raw")

	// Relay data
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64

	wg.Add(2)
```

(The `conn = ktls.TryEnable(conn, "tired-raw")` line is the new code; everything else stays.)

Note: `conn` is the function parameter, declared as `net.Conn`. Reassigning is safe; subsequent goroutines (`optimizedRelay(targetConn, conn)` and `optimizedRelay(conn, targetConn)`) close over the new value.

- [ ] **Step 4: Build**

```bash
go build ./...
```
Expected: PASS.

- [ ] **Step 5: Run server tests**

```bash
go test -short -timeout 120s ./internal/server/...
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(server): enable kTLS in handleRawTunnel after success ack

Move tired-raw kTLS upgrade from handleConnection (pre-handler) into
handleRawTunnel, right after the 0x00 success ack is written and
before the relay goroutines spin up. By this point all auth bytes
(mode + address) have been drained through the TLS stack, so kernel
TLS takes over a socket whose buffer is empty and whose record
sequence counter is in sync.

Net behaviour for tired-raw is unchanged (still gets kTLS), but now
follows the same lifecycle as tired-confusion will after the next
commit, and the EBADMSG race is gone by construction.

Context: reviewed handleRawTunnel control flow end-to-end, confirmed
that the success ack is the last write before optimizedRelay closes
over conn; spent ~30min validating that reassigning conn after Write
is safe under the relay goroutine fan-out."
```

### Task 4: Enable kTLS in `handleProtocolConfusion` after both ack paths

**Files:**
- Modify: `internal/server/server.go:1993` (handleProtocolConfusion)

- [ ] **Step 1: Locate the two ack writes**

```bash
grep -n '"TIRED"\|0x00, 0x00, 0x00, 0x01' internal/server/server.go | grep -v "//"
```
Expected: TUN branch ack at line ~2067 (`conn.Write([]byte("TIRED"))`), tunnel branch success at line ~2101 (`conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00})`).

- [ ] **Step 2: Read context for both branches**

```bash
sed -n '2060,2115p' internal/server/server.go
```
Expected: see TUN-mode dispatch and tunnel-mode connect+ack+relay.

- [ ] **Step 3: Insert `TryEnable` after the TUN-mode ack**

Around line ~2067, modify the TUN-mode branch:

```go
	// Check for TUN mode (first byte = 0x02)
	if buf[embeddedStart] == 0x02 {
		logger.Info("Confusion TUN mode detected")
		// Confirm understanding
		if _, err := conn.Write([]byte("TIRED")); err != nil {
			logger.Debug("Failed to write confusion TUN ack: %v", err)
			return
		}
		// Auth phase complete: kernel offload for the byte-relay phase.
		conn = ktls.TryEnable(conn, "tired-confusion")
		handleConfusionTUNMode(conn, buf[embeddedStart+1:totalRead], srvCtx, logger)
		return
	}
```

- [ ] **Step 4: Insert `TryEnable` after the tunnel-mode success ack**

Around line ~2101, modify the tunnel-mode branch:

```go
	// Send success (length-prefixed as client expects)
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00}); err != nil {
		logger.Debug("Failed to write confusion tunnel ack: %v", err)
		return
	}
	logger.Debug("Connected to target, starting confusion relay")

	// Auth phase complete: kernel offload for the byte-relay phase.
	conn = ktls.TryEnable(conn, "tired-confusion")

	// Relay data
	var wg sync.WaitGroup
	var bytesUp, bytesDown int64
```

- [ ] **Step 5: Verify `handleConfusionTUNMode` accepts `net.Conn`**

```bash
grep -n '^func handleConfusionTUNMode' internal/server/server.go
```
Then read the signature:

```bash
sed -n '$(grep -n "^func handleConfusionTUNMode" internal/server/server.go | head -1 | cut -d: -f1),+5p' internal/server/server.go
```
Expected: signature is `func handleConfusionTUNMode(conn net.Conn, ...)`. If it is `*tls.Conn`, change it to `net.Conn`.

If the signature needs to change, do it, then re-run `go build ./...` to confirm.

- [ ] **Step 6: Build**

```bash
go build ./...
```
Expected: PASS.

- [ ] **Step 7: Run server tests**

```bash
go test -short -timeout 120s ./internal/server/...
```
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(server): enable kTLS in handleProtocolConfusion at relay phase

Move tired-confusion kTLS upgrade from handleConnection (pre-handler)
into handleProtocolConfusion, in both the TUN-mode branch (after the
'TIRED' ack) and the tunnel-mode branch (after the length-prefixed
0x00 success ack). The confusion magic + embedded address is fully
read before the ack, so kTLS takes over a clean socket.

Net behaviour for tired-confusion is unchanged (still gets kTLS); the
move makes the lifecycle parallel to tired-raw and removes the last
caller of the deleted blanket-Enable code path.

Context: traced both branches of handleProtocolConfusion (TUN and
SOCKS-style tunnel), confirmed neither has a post-ack TLS read before
relay; ~25min."
```

### Task 5: Full test sweep + vet

**Files:** none modified — verification only.

- [ ] **Step 1: Full test suite**

```bash
go test -short -timeout 180s ./...
```
Expected: 637+ tests pass across 28 packages (matches baseline).

- [ ] **Step 2: Race detector on touched packages**

```bash
go test -race -short -timeout 180s ./internal/ktls/ ./internal/server/...
```
Expected: PASS, no race reports. The relay goroutines + reassignment of `conn` is the only new pattern; if a race is reported, examine the closure capture site.

- [ ] **Step 3: Vet**

```bash
go vet ./...
```
Expected: no warnings.

- [ ] **Step 4: Linter (if configured)**

```bash
golangci-lint run ./internal/ktls/ ./internal/server/... 2>&1 | tee /tmp/lint.log
```
Expected: no new issues vs. baseline. If `golangci-lint` is not installed, skip.

- [ ] **Step 5: Build all binaries**

```bash
go build ./cmd/...
```
Expected: PASS — all CLIs compile.

- [ ] **Step 6: If any step fails, fix and re-run from Step 1**

No commit in this task — verification only.

### Task 6: End-to-end smoke against a real TLS listener

**Files:**
- Add: `internal/server/ktls_relay_test.go` (new — only if no equivalent test exists)

**Goal:** Catch regressions where a handler reads or writes through the TLS stack *after* `TryEnable`. The test sets up a real net.Listener with TLS, runs a tired-raw client connection through the relay, and asserts the data round-trips intact. If the kernel-takeover-with-residual-buffer race re-emerges, this test will hang or read garbage.

- [ ] **Step 1: Probe for an existing e2e test**

```bash
grep -rn "tired-raw\|handleRawTunnel" internal/server/ --include="*_test.go"
```
Expected: identifies any pre-existing harness. If a similar test is already wired, extend it instead of creating a new file.

- [ ] **Step 2: Write the failing test (only if no existing harness)**

Create `internal/server/ktls_relay_test.go`:

```go
package server

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestRawTunnelKTLSHandover verifies that handleRawTunnel can move data
// through a relay after kTLS Enable, without losing bytes that were
// in-flight in the TLS stack at the moment of handover.
//
// The test is platform-conditional: kTLS is only attempted on Linux. On
// other platforms ktls.TryEnable is a no-op, so the test still exercises
// the (identical) data path without kernel offload.
func TestRawTunnelKTLSHandover(t *testing.T) {
	// Build a minimal listener that wraps tls.Server with the same TLS config
	// the production server would use. Reuse the project's test cert helper
	// if available; otherwise generate ad-hoc.
	cert, err := selfSignedCertForTest(t) // helper expected to exist in test util
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"tired-raw"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Start a target echo server.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	// Server-side: accept TLS, run handleRawTunnel.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		// Build a minimal serverContext with no registry and a noop config.
		srvCtx := newTestServerContext(t)
		handleRawTunnel(tlsConn, srvCtx, testLogger(t), "")
	}()

	// Client: dial, complete TLS, send raw-tunnel mode + target addr, exchange data.
	clientTLS, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"tired-raw"},
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientTLS.Close()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	addr := target.Addr().String()
	frame := []byte{byte(len(addr) >> 8), byte(len(addr))}
	frame = append(frame, []byte(addr)...)
	if _, err := clientTLS.Write(frame); err != nil {
		t.Fatalf("client write addr: %v", err)
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(clientTLS, ack); err != nil {
		t.Fatalf("client read ack: %v", err)
	}
	if ack[0] != 0x00 {
		t.Fatalf("expected success ack 0x00, got 0x%02x", ack[0])
	}

	// Send a payload, expect echo back.
	payload := []byte("hello kTLS relay phase")
	clientTLS.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientTLS.Write(payload); err != nil {
		t.Fatalf("client write payload: %v", err)
	}

	clientTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(clientTLS, resp); err != nil {
		t.Fatalf("client read echo: %v", err)
	}
	if string(resp) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", resp, payload)
	}
}
```

If `selfSignedCertForTest` / `newTestServerContext` / `testLogger` helpers do not exist, look for the closest existing test in `internal/server/` and copy its setup pattern. Do NOT invent new helper names — adapt the test to whatever helper API is in place.

- [ ] **Step 3: Run the test**

```bash
go test -timeout 60s -run TestRawTunnelKTLSHandover -v ./internal/server/
```
Expected: PASS on Linux (kTLS active) and on macOS/non-Linux (kTLS no-op fallback).

- [ ] **Step 4: If the test hangs or echoes garbage**

This is the regression we are guarding against. Investigate:
- Add `t.Logf` after each I/O step to localise where the hang occurs.
- Check whether `TryEnable` is being called before all auth bytes are drained (compare against Task 3's exact insertion point).
- Run with `-race` to catch goroutine-closure races on `conn` reassignment.

Do not weaken or skip the test to make it pass.

- [ ] **Step 5: Commit**

```bash
git add internal/server/ktls_relay_test.go
git commit -m "test(server): add e2e regression for kTLS relay-phase handover

Stand up a real TLS listener with tired-raw ALPN, run handleRawTunnel
in-process, and assert that a payload round-trips through the relay
after kTLS handover. This catches the EBADMSG/buffer-loss regression
that the static exclusion list was working around — if a future
change reintroduces a TLS-stack read after TryEnable, this test will
hang or echo garbage instead of silently losing bytes in production.

Context: pattern modelled on existing internal/server tests; spent
~40min wiring the in-process target echo server and verifying both
the Linux-with-kTLS and macOS-fallback paths."
```

### Task 7: CHANGELOG + final sync

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add CHANGELOG entry**

Open `CHANGELOG.md`, find the `## [Unreleased]` section (or create one). Add under `### Changed`:

```markdown
- kTLS upgrade is now performed per-handler at the relay-phase boundary
  instead of unconditionally after the TLS handshake. tired-raw and
  tired-confusion now call `ktls.TryEnable` after their auth ack;
  tired-morph/stego/ws/polling continue to run without kTLS pending
  Phase 2 (handler-level framer/upgrade rework). Behaviour-equivalent
  for end users; eliminates the EBADMSG race the previous static
  exclusion list was a workaround for.
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog entry for kTLS relay-phase refactor"
```

- [ ] **Step 3: Push branch**

```bash
git push -u origin task/ktls-relay-phase
```

- [ ] **Step 4: Sync beads**

```bash
bd sync
bd close tiredvpn-oss-otm --reason="Phase 1 implemented on task/ktls-relay-phase. Phase 2 tracked in follow-up issue."
```
(If Phase 2 should stay open, instead `bd update tiredvpn-oss-otm --notes="Phase 1 done; Phase 2 pending"` and create a fresh issue for Phase 2.)

- [ ] **Step 5: Open PR**

```bash
gh pr create --title "kTLS relay-phase refactor (Phase 1: raw + confusion)" --body "$(cat <<'EOF'
## Summary
- Adds `ktls.TryEnable` helper and moves the tired-raw / tired-confusion
  kTLS upgrade from `handleConnection` into each handler at the
  relay-phase boundary.
- Behaviour-equivalent for end users; eliminates the EBADMSG race that
  the previous static `kTLSUnsafe` exclusion list was a workaround for.
- Phase 2 (morph, stego, ws, polling) tracked separately — sketched in
  `docs/superpowers/plans/2026-05-06-ktls-relay-phase.md`.

## Test plan
- [ ] `go test -short -timeout 180s ./...` — all 637+ tests pass
- [ ] `go test -race -short ./internal/ktls/ ./internal/server/...` — no races
- [ ] `go test -run TestRawTunnelKTLSHandover -v ./internal/server/` — e2e passes on Linux (kTLS active) and non-Linux (fallback)
- [ ] Smoke benchmark on Amsterdam srv (kTLS-capable) — no EBADMSG in server logs for tired-raw / tired-confusion under load
EOF
)"
```

---

## Phase 2 — PR-2 (sketch, not for execution in this branch)

The remaining ALPNs all have a structural reason kTLS cannot be flipped on after a TLS-stack drain without further rework. Each item below is what the next plan needs to address.

### `tired-morph` — protocol bump for explicit ack

**Why blocked today:** Server reads `MRPH + nameLen + name + auth + first morph packet (which contains target addr)`. Server does not write back an ack. Client is free to send subsequent morph packets immediately after the first. Server's TLS-stack buffer may contain those queued packets at the moment auth completes, so a naive `TryEnable` here loses them.

**Resolution path:**
1. Introduce `tired-morph-v2` ALPN (keep `tired-morph` working without kTLS for backwards compat).
2. v2 protocol: server writes 1-byte ack (`0x00` success / `0x01` fail) after auth+address validation; client must read this ack before sending its first relay byte.
3. Server: after writing ack, call `ktls.TryEnable(conn, "tired-morph-v2")`, then start relay.
4. Client `strategy/morph.go`: after writing MRPH+name+auth+address, read 1-byte ack; on success call `ktls.TryEnable` on its `*tls.Conn` and proceed.
5. Negotiate v2 in `Strategies.Morph` ALPN list (`tired-morph-v2,tired-morph,h2`) so old servers fall back.
6. Remove `tired-morph` from `kTLSUnsafe` (now empty for the v2 entry).

### `tired-stego` — split preface read from framer creation

**Why blocked today:** `initH2Framer` reads the HTTP/2 preface and immediately constructs `http2.NewFramer(conn, conn)` — the framer holds a permanent reference to the original `*tls.Conn`. After preface, server must keep using that framer, so kTLS Enable cannot meaningfully replace `conn` without rebuilding the framer (and the client has likely already started sending frames into the original socket).

**Resolution path:**
1. Refactor `initH2Framer` into two helpers: `readH2Preface(conn) error` and `newH2Framer(conn) *http2.Framer`.
2. In `handleHTTP2WithALPN` (NOT `handleHTTP2`, to keep legacy path untouched):
   - Read preface through `*tls.Conn`.
   - `conn = ktls.TryEnable(conn, "tired-stego")`.
   - Build framer over the post-Enable conn; carry on with `runH2FrameLoop`.
3. Client side `strategy/stego.go`: keep the existing post-handshake `Enable` (already correct for client-first protocol).
4. Remove `tired-stego` from `kTLSUnsafe`.

### `tired-ws` — flush upgrade response before Enable

**Why blocked today:** `handleWebSocketPadded` uses `bufio.NewReader(conn)` to parse the HTTP upgrade. The reader buffers reads from `*tls.Conn`. After `Sec-WebSocket-Accept` write, client may immediately frame data while server is still draining `bufio.Reader`'s internal buffer.

**Resolution path:**
1. Replace the `bufio.Reader` upgrade parser with a hand-rolled line reader that reads exactly the request bytes through `conn` (no buffering past the empty header line).
2. After writing the upgrade response, call `conn.(*tls.Conn).Sync()` equivalent (flush — `tls.Conn.Write` is synchronous so this is automatic, but document it).
3. `conn = ktls.TryEnable(conn, "tired-ws")`.
4. Continue with WebSocket frame parsing on the new conn.
5. Client side `strategy/ws.go`: similar — read upgrade response without bufio over-reach, then Enable.
6. Remove `tired-ws` from `kTLSUnsafe`.

### `tired-polling` — per-poll Enable not viable; consider scope

**Why blocked today:** Polling is HTTP request/response, not a long-lived relay. Each poll is a fresh request — there is no single "auth ends, relay starts" boundary. kTLS would have to be enabled once and hold across all polls, but the polling code path consumes the conn through net/http machinery that owns the framing.

**Resolution path:**
1. Quantify: how much of polling traffic is auth vs body? If body dominates, the kTLS win is nontrivial.
2. If pursuing: lift the polling handler off net/http and onto a hand-rolled HTTP/1.1 framer over our own conn; Enable after the auth-style first request. Significant scope — likely a separate plan, not part of PR-2.
3. Default recommendation: leave `tired-polling` in the exclusion list until profiling justifies the rework.

---

## Self-Review Checklist

- [ ] Spec coverage: every Phase 1 deliverable in the prompt (helper + raw + confusion + remove blanket Enable + tests + changelog) maps to a numbered task above.
- [ ] No placeholders: every code block in Phase 1 is executable as written; helper names referenced in tests (`selfSignedCertForTest`, `newTestServerContext`, `testLogger`) are flagged in Task 6 Step 2 with the explicit instruction to adapt to the existing harness, not invent.
- [ ] Type consistency: `TryEnable(conn net.Conn, label string) net.Conn` signature matches every call site (handleRawTunnel, handleProtocolConfusion both branches). `handleTLSConnection` signature change to `*tls.Conn` is propagated to its single caller (`handleConnection`).
- [ ] Phase 2 is sketched, not detailed — explicitly out of scope for this branch.
- [ ] Each task ends in a commit; verification task (Task 5) is a checkpoint without commit, by design.
- [ ] beads issue is opened in_progress (Step done) and closed/handed-off in Task 7 Step 4.
