package server

import (
	"bytes"
	"sync"
	"testing"

	"golang.org/x/net/http2"
)

// TestForwardH2TUNKeepaliveEcho verifies that the H2-stego TUN ingest path
// echoes a client's zero-length keepalive back to the client (so the client's
// readFromServer deadline resets during idle), matching the morph / confusion /
// native TUN handlers. Before the fix this path dropped pktLen==0 as "invalid"
// (pktLen < 20) and idle H2 clients reconnected every readTimeout (~30s).
func TestForwardH2TUNKeepaliveEcho(t *testing.T) {
	srvCtx := newTestServerContext(t)
	logger := testLogger(t)

	var out bytes.Buffer
	framer := http2.NewFramer(&out, nil)
	var sid uint32 = 1
	h2c := &h2TunConn{
		framer:   framer,
		streamID: &sid,
		cfg:      srvCtx.cfg,
		mu:       &sync.Mutex{},
	}
	// sharedTUN must be non-nil to pass the early guard; the keepalive path
	// never dereferences it, so a zero value is enough.
	tunnel := &h2TunnelState{
		targetConn: h2c,
		streamID:   sid,
		sharedTUN:  &SharedTUN{},
	}

	// Zero-length keepalive: [len:4 = 0]. Must be echoed back (DATA frame out).
	forwardH2TUNPacket(tunnel, sid, []byte{0, 0, 0, 0}, logger)
	if out.Len() == 0 {
		t.Fatal("zero-length keepalive was not echoed back to client")
	}

	// A short non-keepalive frame (1 <= pktLen < 20) is still invalid and must
	// NOT be echoed — only pktLen==0 is a keepalive.
	out.Reset()
	forwardH2TUNPacket(tunnel, sid, []byte{0, 0, 0, 5, 1, 2, 3, 4, 5}, logger)
	if out.Len() != 0 {
		t.Fatalf("short invalid packet should produce no output, got %d bytes", out.Len())
	}
}
