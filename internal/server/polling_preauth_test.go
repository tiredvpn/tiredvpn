package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

// Everything the polling handler reads before the auth check comes from a peer
// nobody has verified: the header block, the body, the session ID. These tests
// hold each of them to a bound, and check that what a peer without a secret
// gets back is what the server always answered for that input.

// pollingRawExchange feeds one request through processHTTPPollingRequest the
// way handleHTTPPolling does (head already read, body on the reader) and
// returns every byte the server wrote back.
func pollingRawExchange(t *testing.T, srvCtx *serverContext, head string, body io.Reader) []byte {
	t.Helper()
	srvEnd, cliEnd := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		cliEnd.SetReadDeadline(time.Now().Add(10 * time.Second))
		io.Copy(&buf, cliEnd)
		got <- buf.Bytes()
	}()
	processHTTPPollingRequest(srvEnd, bufio.NewReader(body), srvCtx, []byte(head), bytes.Repeat([]byte{0x7e}, 32), testLogger(t))
	srvEnd.Close()
	b := <-got
	cliEnd.Close()
	return b
}

func pollingHead(sessionID, token string, ack int64, contentLength int) string {
	return fmt.Sprintf("POST /poll HTTP/1.1\r\nX-Session-ID: %s\r\nX-Auth-Token: %s\r\nX-Ack: %d\r\n"+
		"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n", sessionID, token, ack, contentLength)
}

// pollingAuthFailure is the server's answer to a request whose token does not
// verify - what a peer without a secret sees.
func pollingAuthFailure(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	sendHTTPPollingError(&pollingRecorder{&b}, "Authentication failed")
	return b.Bytes()
}

// TestPollingHeadLineBoundedBeforeAuth: the header block was limited to 16 KiB,
// but the limit was checked only once a whole line had been read, so a line
// without '\n' was buffered for as long as the peer kept sending - 300 MiB per
// connection in the review run, no secret needed. The server must stop reading
// at the limit and close, holding no more than its read buffer.
func TestPollingHeadLineBoundedBeforeAuth(t *testing.T) {
	srvEnd, cliEnd := net.Pipe()
	defer cliEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTPPolling(srvEnd, newTestServerContext(t), []byte("POST /poll HTTP/1.1\r\nX-Session-ID: "), testLogger(t))
	}()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	chunk := bytes.Repeat([]byte{'A'}, 32<<10)
	const offered = 64 << 20
	sent := 0
	cliEnd.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for sent < offered {
		n, err := cliEnd.Write(chunk)
		sent += n
		if err != nil {
			break
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	if sent >= offered {
		t.Fatalf("the server read all %d bytes of a header line without a newline", sent)
	}
	if sent > 2*pollingMaxHeadBytes+len(chunk) {
		t.Fatalf("the server read %d bytes of one header line before giving up; the head limit is %d", sent, pollingMaxHeadBytes)
	}
	if live := int64(after.HeapAlloc) - int64(before.HeapAlloc); live > 1<<20 {
		t.Fatalf("one unauthenticated connection holds %d bytes of heap", live)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not end the connection after an oversized header line")
	}
}

// TestPollingHeadBlockBoundedBeforeAuth: the same limit for a header block made
// of ordinary short lines that never ends with the blank line.
func TestPollingHeadBlockBoundedBeforeAuth(t *testing.T) {
	srvEnd, cliEnd := net.Pipe()
	defer cliEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTPPolling(srvEnd, newTestServerContext(t), []byte("POST /poll HTTP/1.1\r\n"), testLogger(t))
	}()
	line := []byte("X-Pad: " + string(bytes.Repeat([]byte{'A'}, 1000)) + "\r\n")
	sent := 0
	cliEnd.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for sent < 16<<20 {
		n, err := cliEnd.Write(line)
		sent += n
		if err != nil {
			break
		}
	}
	if sent > 2*pollingMaxHeadBytes {
		t.Fatalf("the server read %d bytes of header lines; the head limit is %d", sent, pollingMaxHeadBytes)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not end the connection after an oversized header block")
	}
}

// TestPollingFirstHeadHasDeadline: the first request's header block had no read
// deadline, so a peer that sends half a request holds the connection, a
// goroutine and its buffer for as long as it likes. It now gets the 10s the
// ALPN entry gives its first read. Takes pollingHeadTimeout to run.
func TestPollingFirstHeadHasDeadline(t *testing.T) {
	srvEnd, cliEnd := net.Pipe()
	defer cliEnd.Close()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		handleHTTPPolling(srvEnd, newTestServerContext(t), []byte("POST /poll HTTP/1.1\r\nX-Session-ID: abc"), testLogger(t))
	}()
	select {
	case <-done:
		if took := time.Since(start); took < pollingHeadTimeout-time.Second {
			t.Fatalf("connection ended after %v, before the %v head deadline", took, pollingHeadTimeout)
		}
	case <-time.After(pollingHeadTimeout + 5*time.Second):
		t.Fatalf("a half-sent first request is still holding the connection after %v", pollingHeadTimeout+5*time.Second)
	}
}

// TestPollingPreAuthAnswersMatchAuthFailure (rule 8): the bounds must not give
// a peer without a secret a new answer to tell this server by. For each input
// the old server answered "Authentication failed" (once the body was in), the
// new one must answer the same bytes; an incomplete body still gets "Failed to
// read body", as before.
func TestPollingPreAuthAnswersMatchAuthFailure(t *testing.T) {
	srvCtx := pollingCapServerContext(t, []byte("fx-polling-preauth-secret"))
	want := pollingAuthFailure(t)
	bad := "AAAAAAAAAAAAAAAA"

	cases := []struct {
		name string
		head string
		body []byte
	}{
		{"ordinary 8 KiB body", pollingHead("fxpreauth-normal", bad, 0, 8<<10), make([]byte, 8<<10)},
		{"body over the limit", pollingHead("fxpreauth-oversz", bad, 0, 1<<20), make([]byte, 1<<20)},
		{"one-byte session id", pollingHead("a", bad, 0, 0), nil},
		{"seven-byte session id", pollingHead("abcdefg", bad, 0, 0), nil},
		{"negative content length", pollingHead("fxpreauth-negcl0", bad, 0, -5), nil},
	}
	for _, c := range cases {
		if got := pollingRawExchange(t, srvCtx, c.head, bytes.NewReader(c.body)); !bytes.Equal(got, want) {
			t.Errorf("%s: answered %q, want the auth-failure answer %q", c.name, got, want)
		}
	}

	var incomplete bytes.Buffer
	sendHTTPPollingError(&pollingRecorder{&incomplete}, "Failed to read body")
	for _, announced := range []int{8 << 10, 1 << 20} {
		got := pollingRawExchange(t, srvCtx, pollingHead("fxpreauth-short0", bad, 0, announced), bytes.NewReader(make([]byte, 1024)))
		if !bytes.Equal(got, incomplete.Bytes()) {
			t.Errorf("body of %d announced, 1 KiB sent: answered %q, want %q", announced, got, incomplete.Bytes())
		}
	}
}

// TestPollingOversizedBodyNeverReachesSession pins the body limit's value, not
// just its existence: a body one byte over 64 KiB is refused and never reaches
// the session even with a valid token, while the client's own 8 KiB chunk goes
// through. A limit raised to hundreds of MiB would pass a test that only tries
// 256 MiB.
func TestPollingOversizedBodyNeverReachesSession(t *testing.T) {
	secret := []byte("fx-polling-preauth-secret")
	srvCtx := pollingCapServerContext(t, secret)
	ekm := bytes.Repeat([]byte{0x7e}, 32)
	sess := newPollingSession("fxpreauth-bodylim")
	sess.Secret = secret
	pollingManager.mu.Lock()
	pollingManager.sessions[sess.ID] = sess
	pollingManager.mu.Unlock()
	defer pollingManager.removeSession(sess)

	over := make([]byte, 64<<10+1)
	got := pollingRawExchange(t, srvCtx, pollingHead(sess.ID, pollingTokenFor(sess.ID, secret, ekm), 0, len(over)), bytes.NewReader(over))
	if st := pollingStatusOf(got); st == http.StatusOK {
		t.Fatalf("a %d-byte body was answered %d", len(over), st)
	}
	if up := sess.ReadFromClient(); len(up) != 0 {
		t.Fatalf("a %d-byte body reached the session uplink (%d bytes)", len(over), len(up))
	}

	chunk := bytes.Repeat([]byte{0x42}, 8<<10)
	got = pollingRawExchange(t, srvCtx, pollingHead(sess.ID, pollingTokenFor(sess.ID, secret, ekm), 0, len(chunk)), bytes.NewReader(chunk))
	if st := pollingStatusOf(got); st != http.StatusOK {
		t.Fatalf("the client's own 8 KiB chunk was answered %d", st)
	}
	if up := sess.ReadFromClient(); !bytes.Equal(up, chunk) {
		t.Fatalf("the 8 KiB chunk reached the uplink as %d bytes", len(up))
	}
}

// TestPollingStalePollGetsResetNotNewSession: after the server lost a session -
// swept, or gone with the process on a restart - its client's next poll carries
// an ack and often a body. Opening a fresh session under that ID left one
// nobody reads holding a slot and answered "OK" into the client's data stream.
// Now the ID stays unknown and the client gets one reset frame, the only answer
// client 1.11.5 acts on at once; a second poll for the same dead ID gets the
// auth-failure answer, so a client that keeps polling is not kept alive by an
// endless run of successful polls. The client's real init (no body, nothing
// acked) still opens a session.
func TestPollingStalePollGetsResetNotNewSession(t *testing.T) {
	withPollingLimits(t, 0, 0)
	secret := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, secret)
	ekm := bytes.Repeat([]byte{0x7e}, 32)

	var reset bytes.Buffer
	sendHTTPPollingResponse(&pollingRecorder{&reset}, pollingSessionResetFrame(), false)
	authFail := pollingAuthFailure(t)

	for _, c := range []struct {
		name string
		id   string
		ack  int64
		body []byte
	}{
		{"idle poll with an ack", "fxcap-stale-idle", 12345, nil},
		{"poll with data and an ack", "fxcap-stale-data", 12345, []byte{0, 0, 0, 0}},
		{"poll with data, nothing acked yet", "fxcap-stale-body", 0, []byte{0, 14, '1', '0', '.', '0', '.', '0', '.', '1', ':', '8', '0', '8', '0', 'x'}},
	} {
		t.Cleanup(func() { pollingManager.forgetReset(c.id) })
		got := pollingRawExchange(t, srvCtx, pollingHead(c.id, pollingTokenFor(c.id, secret, ekm), c.ack, len(c.body)), bytes.NewReader(c.body))
		if !bytes.Equal(got, reset.Bytes()) {
			t.Errorf("%s: answered %q, want the reset frame %q", c.name, got, reset.Bytes())
		}
		if pollingManager.Get(c.id) != nil {
			t.Fatalf("%s: a session was opened under an ID the server had dropped", c.name)
		}
		// Second poll for the same dead ID: no more resets.
		got = pollingRawExchange(t, srvCtx, pollingHead(c.id, pollingTokenFor(c.id, secret, ekm), c.ack, len(c.body)), bytes.NewReader(c.body))
		if !bytes.Equal(got, authFail) {
			t.Errorf("%s, polled again: answered %q, want the auth-failure answer %q", c.name, got, authFail)
		}
		if pollingManager.Get(c.id) != nil {
			t.Fatalf("%s, polled again: a session was opened under the dead ID", c.name)
		}
	}

	const initID = "fxcap-stale-init"
	if st := pollingOpen(t, srvCtx, initID, secret); st != http.StatusOK {
		t.Fatalf("the client's init request (no body, ack 0) answered %d", st)
	}
	if pollingManager.Get(initID) == nil {
		t.Fatal("the init request opened no session")
	}
}

// TestPollingResetFrameIsOverTheClientCeiling ties the reset to the only thing
// that makes client 1.11.5 drop a session at once: a downlink frame length over
// the protocol ceiling (maxFrameLen / meekMaxFrame, 65535). A reset the client
// reads as a valid length would be data, and the tunnel would hang until the
// client's health grace expired - 47.9s in a measured restart.
func TestPollingResetFrameIsOverTheClientCeiling(t *testing.T) {
	f := pollingSessionResetFrame()
	if len(f) != 4 {
		t.Fatalf("the reset is %d bytes; the client reads a 4-byte length header", len(f))
	}
	if n := binary.BigEndian.Uint32(f); n <= 65535 {
		t.Fatalf("the reset announces a frame of %d bytes, which the client accepts as data", n)
	}
}

// TestPollingResetBudgetBounded: the bookkeeping of which dead IDs were told
// must not grow without limit, since any authenticated client can invent IDs.
func TestPollingResetBudgetBounded(t *testing.T) {
	now := time.Now()
	for i := range pollingMaxResetIDs + 100 {
		pollingManager.takeResetBudget(fmt.Sprintf("fxcap-budget-%06d", i), now)
	}
	pollingManager.mu.RLock()
	n := len(pollingManager.resetAt)
	pollingManager.mu.RUnlock()
	t.Cleanup(func() {
		for i := range pollingMaxResetIDs + 100 {
			pollingManager.forgetReset(fmt.Sprintf("fxcap-budget-%06d", i))
		}
	})
	if n > pollingMaxResetIDs {
		t.Fatalf("reset bookkeeping holds %d ids, the bound is %d", n, pollingMaxResetIDs)
	}
}

// TestPollingResetUnreachableWithoutSecret (rule 8): the reset frame is a new
// answer on the wire, so a peer that cannot authenticate must never see it. It
// is sent only after the token verifies, which this pins by trying the same
// stale poll with a bad token and with a different client's secret.
func TestPollingResetUnreachableWithoutSecret(t *testing.T) {
	withPollingLimits(t, 0, 0)
	secret := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, secret)
	srvCtx.registry = newTestRegistryWithSecrets(t, map[string]string{"alice": "fx-polling-r3-alice"})
	ekm := bytes.Repeat([]byte{0x7e}, 32)

	var reset bytes.Buffer
	sendHTTPPollingResponse(&pollingRecorder{&reset}, pollingSessionResetFrame(), false)
	want := pollingAuthFailure(t)

	for _, c := range []struct {
		name  string
		id    string
		token string
	}{
		{"made-up token", "fxcap-nosecret-1", "AAAAAAAAAAAAAAAA"},
		{"token for another session id", "fxcap-nosecret-2", pollingTokenFor("fxcap-nosecret-9", secret, ekm)},
		{"token bound to another TLS session", "fxcap-nosecret-3", pollingTokenFor("fxcap-nosecret-3", secret, bytes.Repeat([]byte{0x11}, 32))},
		{"wrong secret", "fxcap-nosecret-4", pollingTokenFor("fxcap-nosecret-4", []byte("fx-polling-r3-not-a-secret"), ekm)},
	} {
		t.Cleanup(func() { pollingManager.forgetReset(c.id) })
		got := pollingRawExchange(t, srvCtx, pollingHead(c.id, c.token, 12345, 0), bytes.NewReader(nil))
		if bytes.Equal(got, reset.Bytes()) {
			t.Fatalf("%s: a peer with no valid secret got the reset frame", c.name)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: answered %q, want the auth-failure answer %q", c.name, got, want)
		}
	}
}
