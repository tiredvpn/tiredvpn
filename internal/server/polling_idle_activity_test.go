package server

import (
	"net"
	"testing"
	"time"
)

// TestPollingIdleSessionStaysRegistered is a side finding of the 2026-10-22
// stand run: an idle HTTP Polling session was cleaned from the shared TUN
// after ~340 s ("cleaned inactive client ... clientID=polling:global") while
// the client kept polling, and the client saw a session reset on a healthy
// idle tunnel. Polls are the Polling client's liveness; the cleanup now sees
// them. Scaled: polls every 100 ms for 2.5 s against a 1 s inactivity limit.
func TestPollingIdleSessionStaysRegistered(t *testing.T) {
	longTest(t)
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.TunIP = net.IPv4(10, 99, 0, 1).To4()
	srvCtx.sharedTUN = newTestSharedTUN(t)
	sess := newPollingSession("idle-polls")
	sess.Origin = "192.0.2.170"
	sess.ClientID = sharedIdentity("global")
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPollingTUNMode(sess, []byte{10, 99, 0, 9, 0x05, 0x00, 0x03}, srvCtx, testLogger(t))
	}()
	t.Cleanup(func() { sess.Close(); <-done })
	waitRegistered(t, srvCtx.sharedTUN, sess)

	for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); {
		time.Sleep(100 * time.Millisecond)
		sess.touch(time.Now()) // an empty poll
	}
	if n := srvCtx.sharedTUN.CleanupInactiveClients(time.Second); n != 0 {
		t.Fatal("a Polling session that kept polling was cleaned as inactive")
	}

	// A session whose polls stopped is still cleaned.
	time.Sleep(2500 * time.Millisecond)
	if n := srvCtx.sharedTUN.CleanupInactiveClients(time.Second); n != 1 {
		t.Fatal("a Polling session with no polls was not cleaned")
	}
}
