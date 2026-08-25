package server

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func mustV6Prefix(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	return n
}

// craftV4Packet builds a minimal IPv4 header with the given destination.
func craftV4Packet(dst net.IP) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[16:20], dst.To4())
	return pkt
}

// craftV6Packet builds a minimal 40-byte IPv6 header with the given destination.
func craftV6Packet(dst net.IP) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	copy(pkt[24:40], dst.To16())
	return pkt
}

// routeKey on an IPv4 packet must behave exactly as the historical inline
// dispatcher: key is the dotted-quad destination.
func TestRouteKeyIPv4Regression(t *testing.T) {
	st := &SharedTUN{}
	pkt := craftV4Packet(net.IPv4(10, 8, 0, 42))
	key, ok := st.routeKey(pkt, len(pkt))
	if !ok || key != "10.8.0.42" {
		t.Fatalf("routeKey(v4) = %q,%v want 10.8.0.42,true", key, ok)
	}

	// Dual-stack configured must not change the v4 path.
	st.v6prefix = mustV6Prefix(t, "fd00:10:8::/64")
	key, ok = st.routeKey(pkt, len(pkt))
	if !ok || key != "10.8.0.42" {
		t.Fatalf("routeKey(v4, dual-stack) = %q,%v want 10.8.0.42,true", key, ok)
	}
}

// Without a dual-stack pool, v6 packets drop exactly as before Phase 2.
func TestRouteKeyV6DroppedWhenV4Only(t *testing.T) {
	st := &SharedTUN{}
	pkt := craftV6Packet(net.ParseIP("fd00:10:8::a08:2"))
	if key, ok := st.routeKey(pkt, len(pkt)); ok || key != "" {
		t.Fatalf("routeKey(v6, no pool) = %q,%v want drop", key, ok)
	}
}

// A v6 packet whose destination is in the pool prefix routes to the SAME
// registry key the client's v4 lease uses (low 32 bits of the address).
func TestRouteKeyV6InPool(t *testing.T) {
	m := NewIPv6Metrics()
	st := &SharedTUN{
		v6prefix: mustV6Prefix(t, "fd00:10:8::/64"),
		v6m:      m,
	}
	// fd00:10:8::a08:2 == prefix | 10.8.0.2
	pkt := craftV6Packet(net.ParseIP("fd00:10:8::a08:2"))
	key, ok := st.routeKey(pkt, len(pkt))
	if !ok || key != "10.8.0.2" {
		t.Fatalf("routeKey(v6 pool dst) = %q,%v want 10.8.0.2,true", key, ok)
	}
	if got := atomic.LoadUint64(&m.tunnelV6Routed); got != 1 {
		t.Fatalf("routed metric = %d, want 1", got)
	}
}

// A v6 packet outside the pool prefix is dropped and counted.
func TestRouteKeyV6NotInPoolDropped(t *testing.T) {
	m := NewIPv6Metrics()
	st := &SharedTUN{
		v6prefix: mustV6Prefix(t, "fd00:10:8::/64"),
		v6m:      m,
	}
	pkt := craftV6Packet(net.ParseIP("2001:db8::1"))
	if key, ok := st.routeKey(pkt, len(pkt)); ok || key != "" {
		t.Fatalf("routeKey(v6 non-pool) = %q,%v want drop", key, ok)
	}
	if got := atomic.LoadUint64(&m.tunnelV6DropNotInPool); got != 1 {
		t.Fatalf("not_in_pool metric = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&m.tunnelV6Routed); got != 0 {
		t.Fatalf("routed metric = %d, want 0", got)
	}
}

// A truncated v6 packet (n < 40) is dropped and counted, never sliced.
func TestRouteKeyV6ShortHeaderDropped(t *testing.T) {
	m := NewIPv6Metrics()
	st := &SharedTUN{
		v6prefix: mustV6Prefix(t, "fd00:10:8::/64"),
		v6m:      m,
	}
	pkt := craftV6Packet(net.ParseIP("fd00:10:8::a08:2"))[:30]
	if key, ok := st.routeKey(pkt, len(pkt)); ok || key != "" {
		t.Fatalf("routeKey(v6 short) = %q,%v want drop", key, ok)
	}
	if got := atomic.LoadUint64(&m.tunnelV6DropShortHdr); got != 1 {
		t.Fatalf("short_header metric = %d, want 1", got)
	}
}

// Drops must not panic when metrics are unavailable (single-secret mode).
func TestRouteKeyV6DropNilMetrics(t *testing.T) {
	st := &SharedTUN{v6prefix: mustV6Prefix(t, "fd00:10:8::/64")}
	if _, ok := st.routeKey(craftV6Packet(net.ParseIP("2001:db8::1")), 40); ok {
		t.Fatal("non-pool v6 routed without metrics")
	}
	if _, ok := st.routeKey(craftV6Packet(net.ParseIP("fd00:10:8::1"))[:30], 30); ok {
		t.Fatal("short v6 routed without metrics")
	}
}

// End-to-end through packetWorker: a v6 packet for a pool client must arrive
// at that client's connection, framed exactly like a v4 packet.
func TestPacketWorkerRoutesV6ToRegisteredClient(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	st := &SharedTUN{
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10),
		stopCh:        make(chan struct{}),
	}
	clientIP := net.IPv4(10, 8, 0, 2)
	st.RegisterClient(clientIP, "v6-client", serverConn, nil)

	payload := craftV6Packet(net.ParseIP("fd00:10:8::a08:2"))
	ch := make(chan *tunPacket, 1)
	ch <- &tunPacket{data: payload, dstIP: "10.8.0.2"} // key as routeKey derived it
	st.wg.Add(1)
	go st.packetWorker(0, ch)

	// Default framing: [len:4][packet], read from the client end of the pipe.
	hdr := make([]byte, 4)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientConn.Read(hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	if got := binary.BigEndian.Uint32(hdr); got != uint32(len(payload)) {
		t.Fatalf("frame len = %d, want %d", got, len(payload))
	}
	body := make([]byte, len(payload))
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientConn.Read(body); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	if body[0]>>4 != 6 {
		t.Fatalf("client received non-v6 packet: version=%d", body[0]>>4)
	}
	if got := net.IP(body[24:40]).String(); got != "fd00:10:8::a08:2" {
		t.Fatalf("client received dst %s, want fd00:10:8::a08:2", got)
	}
}

// A packet keyed to an unregistered client is dropped, not delivered.
func TestPacketWorkerDropsUnknownClient(t *testing.T) {
	st := &SharedTUN{
		clients: make(map[string]*ClientWriter),
		stopCh:  make(chan struct{}),
	}
	ch := make(chan *tunPacket, 1)
	ch <- &tunPacket{data: craftV6Packet(net.ParseIP("fd00:10:8::a08:63")), dstIP: "10.8.0.99"}
	done := make(chan struct{})
	st.wg.Add(1)
	go func() {
		st.packetWorker(0, ch)
		close(done)
	}()
	close(ch)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("packetWorker did not drain and exit")
	}
}
