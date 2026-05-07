package ktls

import (
	"net"
	"testing"
)

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
