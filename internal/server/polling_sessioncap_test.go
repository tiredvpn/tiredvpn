package server

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A polling session costs a relay goroutine, a target connection and up to
// 3 MiB of buffers, and an authenticated client can open as many as it likes
// by inventing session IDs. These tests cover the node-wide ceiling on open
// sessions, the per-client one for registry clients, what a refused client and
// an unauthenticated prober see, and that abandoned sessions give their slot
// back in time.

// withPollingLimits sets the manager's ceilings for one test and puts the
// previous ones back, removing every session the test opened.
func withPollingLimits(t *testing.T, total, perClient int) {
	t.Helper()
	prevTotal, prevPer := pollingManager.limits()
	pollingManager.setLimits(total, perClient)
	t.Cleanup(func() {
		pollingManager.setLimits(prevTotal, prevPer)
		pollingManager.mu.Lock()
		var ours []*HTTPPollingSession
		for id, sess := range pollingManager.sessions {
			if strings.HasPrefix(id, "fxcap-") {
				ours = append(ours, sess)
			}
		}
		pollingManager.mu.Unlock()
		for _, sess := range ours {
			pollingManager.removeSession(sess)
		}
	})
}

// pollingTokenFor builds the request token the client derives (see
// verifyPollingAuth).
func pollingTokenFor(sessionID string, secret, ekm []byte) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s:%d", sessionID, time.Now().Unix())
	h.Write(ekm)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:16]
}

// pollingExchangeRaw sends one bodiless poll the way the client's init request
// does and returns every byte the server wrote back, until it closed or went
// quiet.
func pollingExchangeRaw(t *testing.T, srvCtx *serverContext, sessionID, token string, ekm []byte) []byte {
	t.Helper()
	request := []byte("POST /poll HTTP/1.1\r\nX-Session-ID: " + sessionID + "\r\nX-Auth-Token: " + token +
		"\r\nX-Ack: 0\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
	srvEnd, cliEnd := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		cliEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(&buf, cliEnd)
		got <- buf.Bytes()
	}()
	processHTTPPollingRequest(srvEnd, bufio.NewReader(bytes.NewReader(nil)), srvCtx, request, ekm, testLogger(t))
	srvEnd.Close()
	b := <-got
	cliEnd.Close()
	return b
}

// pollingStatusOf parses the status code of a raw response, -1 if none.
func pollingStatusOf(raw []byte) int {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

func pollingOpen(t *testing.T, srvCtx *serverContext, sessionID string, secret []byte) int {
	t.Helper()
	ekm := bytes.Repeat([]byte{0x7e}, 32)
	return pollingStatusOf(pollingExchangeRaw(t, srvCtx, sessionID, pollingTokenFor(sessionID, secret, ekm), ekm))
}

func pollingCapServerContext(t *testing.T, secret []byte) *serverContext {
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = secret
	return srvCtx
}

// TestPollingSessionCapRefusesOnlyNewSessions: past the node ceiling a new
// session is refused and not created, sessions already open keep working, and
// a slot freed by a closing session can be taken again.
func TestPollingSessionCapRefusesOnlyNewSessions(t *testing.T) {
	withPollingLimits(t, 3, 0)
	secret := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, secret)

	for i := range 3 {
		if st := pollingOpen(t, srvCtx, fmt.Sprintf("fxcap-open-%05d", i), secret); st != http.StatusOK {
			t.Fatalf("session %d of 3 answered %d", i, st)
		}
	}
	if st := pollingOpen(t, srvCtx, "fxcap-open-over1", secret); st == http.StatusOK {
		t.Fatalf("a fourth session past a ceiling of 3 answered %d", st)
	}
	if pollingManager.Get("fxcap-open-over1") != nil {
		t.Fatal("the refused session was created anyway")
	}
	if st := pollingOpen(t, srvCtx, "fxcap-open-00000", secret); st != http.StatusOK {
		t.Fatalf("an open session's next poll answered %d with the node at its ceiling", st)
	}

	pollingManager.removeSession(pollingManager.Get("fxcap-open-00001"))
	if st := pollingOpen(t, srvCtx, "fxcap-open-over2", secret); st != http.StatusOK {
		t.Fatalf("a session after one closed answered %d: the slot was not given back", st)
	}
}

// TestPollingSessionCapPerRegistryClient: a client with its own registry
// secret is held to its own ceiling, which leaves room for everyone else. The
// global secret is one identity for every box that holds it, so it is never
// counted per client.
func TestPollingSessionCapPerRegistryClient(t *testing.T) {
	withPollingLimits(t, 20, 2)
	global := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, global)
	srvCtx.registry = newTestRegistryWithSecrets(t, map[string]string{
		"alice": "fx-polling-cap-alice-secret",
		"bob":   "fx-polling-cap-bob-secret",
	})
	alice, bob := []byte("fx-polling-cap-alice-secret"), []byte("fx-polling-cap-bob-secret")

	for i := range 2 {
		if st := pollingOpen(t, srvCtx, fmt.Sprintf("fxcap-alice-%04d", i), alice); st != http.StatusOK {
			t.Fatalf("alice session %d answered %d", i, st)
		}
	}
	if st := pollingOpen(t, srvCtx, "fxcap-alice-over", alice); st == http.StatusOK {
		t.Fatalf("alice's third session past a per-client ceiling of 2 answered %d", st)
	}
	if st := pollingOpen(t, srvCtx, "fxcap-bob-000000", bob); st != http.StatusOK {
		t.Fatalf("bob was refused (%d) because alice is at her ceiling", st)
	}
	for i := range 3 {
		if st := pollingOpen(t, srvCtx, fmt.Sprintf("fxcap-glob-%05d", i), global); st != http.StatusOK {
			t.Fatalf("global-secret session %d answered %d: the shared identity must not be capped per client", i, st)
		}
	}
}

// TestPollingSessionCapInvisibleBeforeAuth: the ceiling is applied after
// authentication, so a peer without a secret gets byte-for-byte the same
// answer whether the node is full or empty. A refused client gets the busy
// answer the server already sends for a full uplink, not a new one.
func TestPollingSessionCapInvisibleBeforeAuth(t *testing.T) {
	withPollingLimits(t, 1, 0)
	secret := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, secret)
	ekm := bytes.Repeat([]byte{0x7e}, 32)

	emptyNode := pollingExchangeRaw(t, srvCtx, "fxcap-probe-0000", "AAAAAAAAAAAAAAAA", ekm)
	if st := pollingOpen(t, srvCtx, "fxcap-fill-00000", secret); st != http.StatusOK {
		t.Fatalf("filling the ceiling answered %d", st)
	}
	fullNode := pollingExchangeRaw(t, srvCtx, "fxcap-probe-0000", "AAAAAAAAAAAAAAAA", ekm)
	if !bytes.Equal(emptyNode, fullNode) {
		t.Fatalf("an unauthenticated peer can tell a full node from an empty one:\nempty: %q\nfull:  %q", emptyNode, fullNode)
	}

	refused := pollingExchangeRaw(t, srvCtx, "fxcap-refused-00", pollingTokenFor("fxcap-refused-00", secret, ekm), ekm)
	var busy bytes.Buffer
	sendHTTPPollingBusy(&pollingRecorder{&busy})
	if !bytes.Equal(refused, busy.Bytes()) {
		t.Fatalf("a refused session got %q, want the existing busy answer %q", refused, busy.Bytes())
	}
}

// pollingRecorder is a net.Conn that only records writes.
type pollingRecorder struct{ w io.Writer }

func (r *pollingRecorder) Read([]byte) (int, error)         { return 0, io.EOF }
func (r *pollingRecorder) Write(p []byte) (int, error)      { return r.w.Write(p) }
func (r *pollingRecorder) Close() error                     { return nil }
func (r *pollingRecorder) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (r *pollingRecorder) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (r *pollingRecorder) SetDeadline(time.Time) error      { return nil }
func (r *pollingRecorder) SetReadDeadline(time.Time) error  { return nil }
func (r *pollingRecorder) SetWriteDeadline(time.Time) error { return nil }

// TestPollingAbandonedSessionReleasedInTime: the client never says goodbye, so
// an abandoned session holds its slot until the idle sweep takes it. A live
// client polls at least every pollIdleMax (4s, +25% jitter) and gives a session
// up itself after 20s without a successful poll, so a session silent for 90s
// has no client left; it used to be kept for five minutes, long enough for
// dead sessions to fill the ceiling. A session polled a few seconds ago stays.
func TestPollingAbandonedSessionReleasedInTime(t *testing.T) {
	withPollingLimits(t, 0, 0)
	now := time.Now()
	dead := newPollingSession("fxcap-dead-00000")
	dead.touch(now.Add(-90 * time.Second))
	live := newPollingSession("fxcap-live-00000")
	live.touch(now.Add(-5 * time.Second))
	// Closed but still polled: nothing relays for it any more.
	closedRecent := newPollingSession("fxcap-closed-000")
	closedRecent.touch(now)
	closedRecent.Close()
	pollingManager.mu.Lock()
	pollingManager.sessions[dead.ID] = dead
	pollingManager.sessions[live.ID] = live
	pollingManager.sessions[closedRecent.ID] = closedRecent
	pollingManager.mu.Unlock()

	pollingManager.cleanup()

	if pollingManager.Get(dead.ID) != nil {
		t.Fatal("a session silent for 90s is still holding a slot")
	}
	if !dead.closed.Load() {
		t.Fatal("the swept session was not closed, its relay keeps running")
	}
	if pollingManager.Get(live.ID) == nil {
		t.Fatal("a session polled 5s ago was swept")
	}
	if pollingManager.Get(closedRecent.ID) != nil {
		t.Fatal("a closed session kept its slot because its client is still polling")
	}
	if pollingManager.cleanupInterval > 15*time.Second {
		t.Fatalf("sweep runs every %v: a dead session can sit past its timeout that much longer", pollingManager.cleanupInterval)
	}
}

// TestPollingLateRelayKeepsNewerSession: relays remove their session when they
// end. If the sweep took the session first and the client re-polled the ID, a
// newer session now sits under it; removing by ID took that one out too, a live
// session gone while its relay kept running outside the count.
func TestPollingLateRelayKeepsNewerSession(t *testing.T) {
	withPollingLimits(t, 0, 0)
	old := newPollingSession("fxcap-reused-id0")
	newer := newPollingSession("fxcap-reused-id0")
	pollingManager.mu.Lock()
	pollingManager.sessions[newer.ID] = newer
	pollingManager.mu.Unlock()

	pollingManager.removeSession(old)

	if pollingManager.Get(newer.ID) != newer {
		t.Fatal("a relay ending late removed the newer session that reuses its ID")
	}
	if !old.closed.Load() {
		t.Fatal("the late relay's own session was not closed")
	}
}

// TestPollingPollKeepsSessionAlive: a request on an open session is what tells
// the sweep the client is still there. A shorter idle timeout is only safe if
// every poll refreshes it.
func TestPollingPollKeepsSessionAlive(t *testing.T) {
	withPollingLimits(t, 0, 0)
	secret := []byte("fx-polling-cap-global-secret")
	srvCtx := pollingCapServerContext(t, secret)
	if st := pollingOpen(t, srvCtx, "fxcap-alive-0000", secret); st != http.StatusOK {
		t.Fatalf("opening the session answered %d", st)
	}
	sess := pollingManager.Get("fxcap-alive-0000")
	sess.touch(time.Now().Add(-90 * time.Second))

	if st := pollingOpen(t, srvCtx, "fxcap-alive-0000", secret); st != http.StatusOK {
		t.Fatalf("polling the session answered %d", st)
	}
	pollingManager.cleanup()
	if pollingManager.Get("fxcap-alive-0000") != sess {
		t.Fatal("a session polled just now was swept as idle")
	}
}
