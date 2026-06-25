package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

// resetAdmission restores the global admission semaphore after a test.
func resetAdmission(t *testing.T) {
	t.Helper()
	prev := admissionSem
	t.Cleanup(func() { admissionSem = prev })
}

// TestInitAdmissionControlDefault verifies the semaphore falls back to the
// default capacity when no limit is configured.
func TestInitAdmissionControlDefault(t *testing.T) {
	resetAdmission(t)
	initAdmissionControl(&Config{MaxConcurrentConns: 0})
	if got := cap(admissionSem); got != defaultMaxConcurrentConns {
		t.Fatalf("default cap = %d, want %d", got, defaultMaxConcurrentConns)
	}
}

// TestInitAdmissionControlExplicit verifies an explicit limit is honoured.
func TestInitAdmissionControlExplicit(t *testing.T) {
	resetAdmission(t)
	initAdmissionControl(&Config{MaxConcurrentConns: 7})
	if got := cap(admissionSem); got != 7 {
		t.Fatalf("explicit cap = %d, want 7", got)
	}
}

// blockingConn wraps a net.Conn and signals when Close is called.
type blockingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (b *blockingConn) Close() error {
	b.once.Do(func() { close(b.closed) })
	return b.Conn.Close()
}

// TestAcceptConnectionDropsOnOverflow verifies that once the admission limit is
// reached, further connections are dropped (closed) immediately rather than
// spawning a handler goroutine. This is the OOM guard under a reconnect storm.
func TestAcceptConnectionDropsOnOverflow(t *testing.T) {
	resetAdmission(t)
	const limit = 3
	initAdmissionControl(&Config{MaxConcurrentConns: limit})

	srvCtx := &serverContext{cfg: &Config{}}

	// Block every admitted handler so admitted slots stay occupied. We model the
	// handler by pre-filling the semaphore directly: occupy all slots so the next
	// acceptConnection must take the drop path. We then assert the connection is
	// closed and no slot leaks.
	for i := 0; i < limit; i++ {
		admissionSem <- struct{}{}
	}
	if len(admissionSem) != limit {
		t.Fatalf("setup: occupied %d slots, want %d", len(admissionSem), limit)
	}

	// All slots taken: the next connection must be dropped and closed.
	c0, c1 := net.Pipe()
	defer c1.Close()
	bc := &blockingConn{Conn: c0, closed: make(chan struct{})}

	admitted := acceptConnection(bc, srvCtx, 999)
	if admitted {
		t.Fatal("acceptConnection admitted a connection past the limit")
	}
	select {
	case <-bc.closed:
		// good: overflow connection was closed
	case <-time.After(time.Second):
		t.Fatal("overflow connection was not closed")
	}
	if len(admissionSem) != limit {
		t.Fatalf("semaphore leaked: len=%d, want %d", len(admissionSem), limit)
	}
}

// TestAcceptConnectionAdmitsAndReleases verifies that an admitted connection
// occupies exactly one slot while its handler runs and releases it on exit, so
// the limit is reusable (no leak across the connection lifecycle).
func TestAcceptConnectionAdmitsAndReleases(t *testing.T) {
	resetAdmission(t)
	initAdmissionControl(&Config{MaxConcurrentConns: 2})
	srvCtx := &serverContext{cfg: &Config{}}

	// Drive a connection through handleConnection. The peer is closed
	// immediately so handleConnection's read fails fast and the handler exits,
	// releasing the slot.
	c0, c1 := net.Pipe()
	c1.Close() // peer gone -> handler returns quickly

	if !acceptConnection(c0, srvCtx, 1) {
		t.Fatal("expected first connection to be admitted")
	}

	// Wait for the slot to be released (handler exits and drains the semaphore).
	deadline := time.After(2 * time.Second)
	for len(admissionSem) != 0 {
		select {
		case <-deadline:
			t.Fatalf("slot not released: len=%d", len(admissionSem))
		case <-time.After(5 * time.Millisecond):
		}
	}
}
