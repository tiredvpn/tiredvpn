package server

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestSharedTUN builds a SharedTUN with everything the client registry needs
// and nothing that requires a real TUN device (which needs root). The
// dispatcher and TUN writes are deliberately out of scope here.
func newTestSharedTUN(t *testing.T) *SharedTUN {
	t.Helper()
	return &SharedTUN{
		name:          "tiredvpn-test",
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10),
		stopCh:        make(chan struct{}),
	}
}

// TestHashIP pins the worker-selection hash. It must be deterministic (the same
// client always lands on the same worker, so its packets stay in order) and
// never negative, because the caller indexes a slice with it.
func TestHashIP(t *testing.T) {
	for _, ip := range []string{
		"", "10.8.0.2", "10.8.0.254", "255.255.255.255",
		"fd00:10:8::a08:2", "0.0.0.0",
	} {
		h := hashIP(ip)
		if h < 0 {
			t.Errorf("hashIP(%q) = %d, want a non-negative index", ip, h)
		}
		if again := hashIP(ip); again != h {
			t.Errorf("hashIP(%q) is not deterministic: %d then %d", ip, h, again)
		}
	}

	// Distinct addresses in a /24 must spread across workers rather than all
	// landing on one, or the pool serialises onto a single goroutine.
	const workers = 8
	buckets := make(map[int]int, workers)
	for i := 2; i < 255; i++ {
		ip := net.IPv4(10, 8, 0, byte(i)).String()
		buckets[hashIP(ip)%workers]++
	}
	if len(buckets) < workers/2 {
		t.Errorf("253 addresses hashed into only %d of %d workers", len(buckets), workers)
	}
}

// TestSharedTUNRegisterUnregister covers the client registry lifecycle. A
// client left in the map after disconnect keeps receiving packets destined for
// an address that has been reassigned.
func TestSharedTUNRegisterUnregister(t *testing.T) {
	st := newTestSharedTUN(t)

	if got := st.ClientCount(); got != 0 {
		t.Fatalf("fresh SharedTUN has %d clients, want 0", got)
	}
	if got := st.Name(); got != "tiredvpn-test" {
		t.Errorf("Name() = %q, want tiredvpn-test", got)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	clientIP := net.IPv4(10, 8, 0, 2)
	writer := st.RegisterClient(clientIP, "client-a", serverConn, nil)
	if writer == nil {
		t.Fatal("RegisterClient returned nil")
	}
	if got := st.ClientCount(); got != 1 {
		t.Errorf("ClientCount = %d, want 1", got)
	}

	select {
	case <-writer.Done():
		t.Fatal("a freshly registered client is already done")
	default:
	}

	st.UnregisterClient(clientIP, writer)
	if got := st.ClientCount(); got != 0 {
		t.Errorf("ClientCount = %d after unregister, want 0", got)
	}
	select {
	case <-writer.Done():
	default:
		t.Error("Done() was not closed on unregister; the transport read loop would hang")
	}

	// Unregistering twice, or unregistering an address that was never
	// registered, must be a no-op rather than a double-close panic.
	st.UnregisterClient(clientIP, writer)
	st.UnregisterClient(net.IPv4(10, 8, 0, 99), nil)
}

// TestSharedTUNUnregisterRespectsExpectedWriter guards the reconnect race: a
// client that reconnects replaces its writer, and the OLD connection's deferred
// cleanup must not tear down the NEW one. Getting this wrong disconnects a
// client every time it reconnects quickly.
func TestSharedTUNUnregisterRespectsExpectedWriter(t *testing.T) {
	st := newTestSharedTUN(t)
	clientIP := net.IPv4(10, 8, 0, 2)

	oldConn, oldPeer := net.Pipe()
	defer oldConn.Close()
	defer oldPeer.Close()
	oldWriter := st.RegisterClient(clientIP, "client-a", oldConn, nil)

	newConn, newPeer := net.Pipe()
	defer newConn.Close()
	defer newPeer.Close()
	newWriter := st.RegisterClient(clientIP, "client-a", newConn, nil)

	if oldWriter == newWriter {
		t.Fatal("reconnect reused the same writer; the race this guards cannot occur")
	}
	if got := st.ClientCount(); got != 1 {
		t.Errorf("ClientCount = %d after replacement, want 1", got)
	}

	// The stale connection's cleanup fires late and must be ignored.
	st.UnregisterClient(clientIP, oldWriter)
	if got := st.ClientCount(); got != 1 {
		t.Fatalf("the old connection's cleanup evicted the live client (count=%d)", got)
	}
	select {
	case <-newWriter.Done():
		t.Fatal("the live client's Done() was closed by the stale connection's cleanup")
	default:
	}

	// A nil expectedWriter means "unconditional", which is what the shutdown
	// path uses.
	st.UnregisterClient(clientIP, nil)
	if got := st.ClientCount(); got != 0 {
		t.Errorf("ClientCount = %d after an unconditional unregister, want 0", got)
	}
}

// TestSharedTUNCleanupInactiveClients covers the idle reaper. Timestamps are
// set directly rather than waited on, so the test carries no timing dependence.
func TestSharedTUNCleanupInactiveClients(t *testing.T) {
	st := newTestSharedTUN(t)

	conns := make([]net.Conn, 0, 6)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	register := func(last byte, inactiveFor time.Duration) *ClientWriter {
		a, b := net.Pipe()
		conns = append(conns, a, b)
		ip := net.IPv4(10, 8, 0, last)
		w := st.RegisterClient(ip, "client-"+ip.String(), a, nil)
		atomic.StoreInt64(&w.lastActive, time.Now().Add(-inactiveFor).Unix())
		return w
	}

	fresh := register(2, 0)
	idle := register(3, time.Hour)
	borderline := register(4, 90*time.Second)

	cleaned := st.CleanupInactiveClients(2 * time.Minute)
	if cleaned != 1 {
		t.Fatalf("CleanupInactiveClients removed %d clients, want 1", cleaned)
	}
	if got := st.ClientCount(); got != 2 {
		t.Errorf("ClientCount = %d after cleanup, want 2", got)
	}
	select {
	case <-idle.Done():
	default:
		t.Error("the reaped client's Done() was not closed")
	}
	for name, w := range map[string]*ClientWriter{"fresh": fresh, "borderline": borderline} {
		select {
		case <-w.Done():
			t.Errorf("the %s client was reaped while still within the idle window", name)
		default:
		}
	}

	// UpdateActivity must rescue a client from the next sweep, which is what
	// keeps a quiet but live tunnel from being torn down.
	atomic.StoreInt64(&fresh.lastActive, time.Now().Add(-time.Hour).Unix())
	fresh.UpdateActivity()
	if cleaned := st.CleanupInactiveClients(2 * time.Minute); cleaned != 0 {
		t.Errorf("cleanup removed %d clients after UpdateActivity, want 0", cleaned)
	}

	// A zero window reaps anything whose last activity is in the past. The
	// client that just called UpdateActivity has now-lastActive == 0, which is
	// not strictly greater than the window, so it survives — age is compared
	// with >, not >=.
	if cleaned := st.CleanupInactiveClients(0); cleaned != 1 {
		t.Errorf("zero-window sweep removed %d clients, want 1 (the borderline one)", cleaned)
	}
	if got := st.ClientCount(); got != 1 {
		t.Errorf("ClientCount = %d, want 1 (the just-active client survives a zero window)", got)
	}

	// Age it and it goes too.
	atomic.StoreInt64(&fresh.lastActive, time.Now().Add(-time.Second).Unix())
	if cleaned := st.CleanupInactiveClients(0); cleaned != 1 {
		t.Errorf("zero-window sweep removed %d clients, want 1", cleaned)
	}
	if got := st.ClientCount(); got != 0 {
		t.Errorf("ClientCount = %d, want 0", got)
	}
	// A sweep over an empty registry is harmless.
	if cleaned := st.CleanupInactiveClients(0); cleaned != 0 {
		t.Errorf("sweep over an empty registry removed %d clients", cleaned)
	}
}

// TestSharedTUNPacketPool covers the buffer recycling on the dispatch hot path.
// A packet that comes back from the pool still carrying the previous
// destination would be delivered to the wrong client.
func TestSharedTUNPacketPool(t *testing.T) {
	st := newTestSharedTUN(t)
	st.mtu = 1400
	st.pktPool = sync.Pool{New: func() any {
		return &tunPacket{buf: make([]byte, st.mtu+100)}
	}}

	pkt := st.getPacket()
	if pkt == nil {
		t.Fatal("getPacket returned nil")
	}
	if len(pkt.buf) != st.mtu+100 {
		t.Errorf("pooled buffer = %d bytes, want %d", len(pkt.buf), st.mtu+100)
	}

	pkt.data = pkt.buf[:20]
	pkt.dstIP = "10.8.0.2"
	st.releasePacket(pkt)

	if pkt.data != nil {
		t.Error("released packet still references its payload; the buffer stays pinned")
	}
	if pkt.dstIP != "" {
		t.Errorf("released packet still carries dstIP %q; it could be delivered to the wrong client", pkt.dstIP)
	}

	// A second take must hand back a usable packet, whether pooled or fresh.
	next := st.getPacket()
	if next == nil || len(next.buf) != st.mtu+100 {
		t.Fatalf("getPacket after release returned %+v", next)
	}
	if next.dstIP != "" || next.data != nil {
		t.Errorf("recycled packet is not clean: %+v", next)
	}
}

// TestLocalTUNSinkLifecycle covers the exit-side sink's lifecycle methods. Its
// Close must unregister the client exactly once, however many transports call
// it: a double unregister would evict whatever client took the address next.
func TestLocalTUNSinkLifecycle(t *testing.T) {
	st := newTestSharedTUN(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	clientIP := net.IPv4(10, 8, 0, 2)
	writer := st.RegisterClient(clientIP, "client-a", serverConn, nil)

	sink := newLocalTUNSink(st, writer, clientIP)
	if sink == nil {
		t.Fatal("newLocalTUNSink returned nil")
	}

	// Done tracks the writer, which is how the transport read loop learns the
	// client went away.
	select {
	case <-sink.Done():
		t.Fatal("a fresh sink is already done")
	default:
	}
	sink.UpdateActivity()

	sink.Close()
	if got := st.ClientCount(); got != 0 {
		t.Errorf("ClientCount = %d after sink.Close, want 0", got)
	}
	select {
	case <-sink.Done():
	default:
		t.Error("sink.Close did not close the writer's done channel")
	}

	// Re-register a different client on the same address, then close the stale
	// sink again: the sync.Once must stop it from evicting the newcomer.
	newConn, newPeer := net.Pipe()
	defer newConn.Close()
	defer newPeer.Close()
	st.RegisterClient(clientIP, "client-b", newConn, nil)

	sink.Close()
	sink.Close()
	if got := st.ClientCount(); got != 1 {
		t.Errorf("a repeated Close on a stale sink evicted the new client (count=%d)", got)
	}
}

// TestRelayTUNSinkUpdateActivityIsNoOp pins the deliberate no-op. The upstream
// leg's liveness comes from the read deadline in pump, so this method must not
// grow an idle timer that could tear down a healthy relay.
func TestRelayTUNSinkUpdateActivityIsNoOp(t *testing.T) {
	up, peer := net.Pipe()
	defer peer.Close()

	sink := &relayTUNSink{up: up, logger: testLogger(t), done: make(chan struct{})}
	sink.UpdateActivity()
	sink.UpdateActivity()

	select {
	case <-sink.Done():
		t.Error("UpdateActivity closed the sink")
	default:
	}

	sink.Close()
	select {
	case <-sink.Done():
	default:
		t.Error("Close did not signal Done")
	}
	// Close is documented as safe to call more than once.
	sink.Close()
}

// TestRelayTUNSinkWritePacketRejectsOversize pins the frame ceiling. The length
// prefix is 32-bit but an IP packet cannot exceed 65535, so anything larger is
// a desynced stream; framing it anyway would corrupt the upstream leg.
func TestRelayTUNSinkWritePacketRejectsOversize(t *testing.T) {
	up, peer := net.Pipe()
	defer up.Close()
	defer peer.Close()

	sink := &relayTUNSink{up: up, logger: testLogger(t), done: make(chan struct{})}
	err := sink.WritePacket(make([]byte, 65536))
	if err == nil {
		t.Fatal("a 65536-byte packet was accepted")
	}
	sink.Close()
}

// TestInitREALITYKeys covers key generation at startup. Two calls must produce
// different key pairs, and the public key must be derived from the private one
// each time: a stale or zero public key would make every REALITY handshake fail
// with no obvious cause.
func TestInitREALITYKeys(t *testing.T) {
	if err := InitREALITYKeys(); err != nil {
		t.Fatalf("InitREALITYKeys: %v", err)
	}

	realityKeyMu.RLock()
	firstPriv, firstPub := serverREALITYPrivKey, serverREALITYPubKey
	realityKeyMu.RUnlock()

	var zero [32]byte
	if firstPriv == zero {
		t.Error("private key is all zeroes")
	}
	if firstPub == zero {
		t.Error("public key is all zeroes")
	}

	if err := InitREALITYKeys(); err != nil {
		t.Fatalf("second InitREALITYKeys: %v", err)
	}
	realityKeyMu.RLock()
	secondPriv, secondPub := serverREALITYPrivKey, serverREALITYPubKey
	realityKeyMu.RUnlock()

	if secondPriv == firstPriv {
		t.Error("two initialisations produced the same private key")
	}
	if secondPub == firstPub {
		t.Error("two initialisations produced the same public key")
	}
}

// TestWarnIfNoGlobalIPv6Uplink exercises the startup guard. It only logs, so
// the assertion is that it inspects real interfaces without panicking or
// blocking, whatever this machine's addressing looks like.
func TestWarnIfNoGlobalIPv6Uplink(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		warnIfNoGlobalIPv6Uplink()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("warnIfNoGlobalIPv6Uplink blocked; it runs on the startup path")
	}
}
