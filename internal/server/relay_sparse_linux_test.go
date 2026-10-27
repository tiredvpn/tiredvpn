package server

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// The fix12-slow stand run: the exit sends the client 28 B every 5 s and
// nothing goes up. That is more often than every 9 s, so a desktop client
// older than 1.11.9 sends no keepalive, and a sparse download feeds no
// WINDOW_UPDATE. On the TUN bridge the relay sent nothing either - it had
// no keepalive - and the exit closed the leg after exactly 60 s without a
// frame, twelve times in 15 minutes. These run the stand's shape, scaled
// 1:25 (a datagram every 200 ms, the exit's deadline 2.4 s), for five of
// the exit's deadlines, through every relay path into a real exit: the
// sink, the bridge, and a proxy relay over UpstreamDialer.Dial.

// sparseEvery is the stand's 5 s between two datagrams down, scaled.
const sparseEvery = 5 * time.Second / legScale

// sparseDownload sends the client a 28-byte datagram every sparseEvery for
// five of the exit's read deadlines and fails the test if the exit ends the
// client's session meanwhile. It returns how many were sent.
func sparseDownload(t *testing.T, exit *legExit, clientIP net.IP) int64 {
	t.Helper()
	w := exitWriterFor(t, exit, clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), clientIP)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	span := legDeadlines * h2FrameReadTimeout()
	var sent int64
	tick := time.NewTicker(sparseEvery)
	defer tick.Stop()
	for range span / sparseEvery {
		<-tick.C
		if w.SendPacket(pkt) == nil {
			sent++
		}
		if n := exit.ended.Load(); n != 0 {
			t.Fatalf("the exit ended the leg after %d datagrams, %v in (read deadline %v)",
				sent, time.Duration(sent)*sparseEvery, h2FrameReadTimeout())
		}
	}
	return sent
}

// TestAnOldClientOnASparseDownloadKeepsItsBridgeLeg is the stand run
// itself, on its own path: a 1.11.8-like client over anti-probe, which the
// relay terminates in handleRawTunnel and bridges (relayTUNToUpstream).
func TestAnOldClientOnASparseDownloadKeepsItsBridgeLeg(t *testing.T) {
	longLegTest(t)
	scaleLegClocks(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)
	client := clientVia(t, relay, false, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewAntiProbeStrategy(m, secret)
	})
	sent := sparseDownload(t, exit, client.LocalIP())
	waitDown(t, client, sent)
}

// TestAnOldClientOnASparseDownloadKeepsItsSinkLeg: the same client over
// Traffic Morph, which the relay terminates itself and forwards through a
// relayTUNSink. Its keepalive was there, but stopped once the client had
// been silent for a minute (relayClientActiveWindow), while Morph's own
// read deadline on the client gives it 120 s: the leg died in between.
// Over HTTP/2 Stego the two are the same 60 s, and a client that sends
// nothing loses its session to the relay's own deadline, as it would
// straight to an exit; no relay keepalive can hold that one.
func TestAnOldClientOnASparseDownloadKeepsItsSinkLeg(t *testing.T) {
	longLegTest(t)
	scaleLegClocks(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)
	client := clientVia(t, relay, false, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewTrafficMorphStrategy(m, nil, nil, secret)
	})
	sent := sparseDownload(t, exit, client.LocalIP())
	waitDown(t, client, sent)
}

// waitDown waits for the datagrams sent down to reach the client.
func waitDown(t *testing.T, client *tun.VPNClient, sent int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, down, _, _ := client.Stats(); down >= sent*9/10 {
			return
		}
		if time.Now().After(deadline) {
			_, down, _, _ := client.Stats()
			t.Fatalf("%d of %d datagrams came down", down, sent)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestASparseDownloadThroughAProxyRelayKeepsItsLeg: a proxy relay -
// handleRawTunnel over UpstreamDialer.Dial, copying with optimizedRelay -
// with the target sending 28 B every 5 s and the client nothing, scaled.
// The client's TCP acknowledges what comes down; at the end "hello" up has
// to reach the target, which must have got nothing else.
func TestASparseDownloadThroughAProxyRelayKeepsItsLeg(t *testing.T) {
	longLegTest(t)
	scaleLegClocks(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	stop := make(chan struct{})
	stopTarget := sync.OnceFunc(func() { close(stop) })
	t.Cleanup(stopTarget)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		go func() {
			b, _ := io.ReadAll(c)
			got <- b
		}()
		tick := time.NewTicker(sparseEvery)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if _, err := c.Write(make([]byte, 28)); err != nil {
					return
				}
			}
		}
	}()

	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, secret)}
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleRawTunnel(relaySide, relayCtx, testLogger(t), clientIdentity{})
	}()
	addr := []byte(ln.Addr().String())
	if _, err := client.Write(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("relay ack %x: %v", ack, err)
	}
	_ = client.SetReadDeadline(time.Time{})
	var down atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			down.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	for end := time.Now().Add(legDeadlines * h2FrameReadTimeout()); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		select {
		case <-done:
			t.Fatalf("the relay closed the tunnel after %d bytes down", down.Load())
		default:
		}
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	client.Close()
	stopTarget()
	select {
	case b := <-got:
		if string(b) != "hello" {
			t.Fatalf("the target got %q, want the client's hello and nothing else", b)
		}
	case <-time.After(3 * h2FrameReadTimeout()):
		t.Fatal("the target never saw the end of the client's stream")
	}
}

// TestAGoneClientLetsTheBridgeLegGo is the other side of the rule: a client
// neither heard from nor acknowledging anything for the window is gone, and
// the relay stops feeding its leg, which the exit's deadline then ends. Here
// nothing flows either way after the setup.
//
// The round-9 review (P3-10) read this as a client production would keep
// alive, because the kernel's keepalive would be answered within the window.
// Measured on loopback, it is not: with keepalive at 1 s on both ends, a
// conn's tcpi_last_ack_recv was refreshed once by the ACK of the data sent
// and then grew past 7 s untouched - keepalive probes do not refresh it. So
// a client the relay sends nothing to does go away by this rule, whatever
// its socket. A client the relay keeps sending to - the sparse download
// above - is the case the rule holds, and the one it was changed for.
func TestAGoneClientLetsTheBridgeLegGo(t *testing.T) {
	scaleLegClocks(t)
	b := startRelayBridge(t)
	deadline := time.Now().Add(relayClientActiveWindow() + 3*h2FrameReadTimeout())
	for b.exit.ended.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.exit.ended.Load() == 0 {
		t.Fatalf("the relay kept a silent client's leg for %v", relayClientActiveWindow()+3*h2FrameReadTimeout())
	}
}

// TestAClientThatHungUpLetsTheBridgeLegGo: a client whose socket is gone
// acknowledges nothing either, and its leg goes the same way.
func TestAClientThatHungUpLetsTheBridgeLegGo(t *testing.T) {
	scaleLegClocks(t)
	b := startRelayBridge(t)
	b.client.Close()
	deadline := time.Now().Add(relayClientActiveWindow() + 3*h2FrameReadTimeout())
	for b.exit.ended.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.exit.ended.Load() == 0 {
		t.Fatalf("the relay kept the leg of a client that hung up for %v",
			relayClientActiveWindow()+3*h2FrameReadTimeout())
	}
}

// TestClientLiveness: heard within the window is alive; so is a TCP that
// acknowledged data within it, a Polling session with a request within it
// and an open QUIC conn; a TCP that has acknowledged nothing for the
// window, a closed QUIC conn, or no conn at all, is not.
func TestClientLiveness(t *testing.T) {
	old := relayClientActiveWindowNs.Load()
	relayClientActiveWindowNs.Store(int64(300 * time.Millisecond))
	t.Cleanup(func() { relayClientActiveWindowNs.Store(old) })
	never := func() (time.Duration, bool) { return 0, false }
	if (clientLiveness{heard: func() (time.Duration, bool) { return 10 * time.Millisecond, true }}).alive() == false {
		t.Fatal("a client heard 10 ms ago is not alive")
	}
	if (clientLiveness{heard: never}).alive() {
		t.Fatal("a client never heard, with no conn, is alive")
	}
	if !(clientLiveness{heard: never, seen: func() (time.Duration, bool) { return 10 * time.Millisecond, true }}).alive() {
		t.Fatal("a Polling client seen 10 ms ago is not alive")
	}
	if (clientLiveness{heard: never, seen: func() (time.Duration, bool) { return time.Second, true }}).alive() {
		t.Fatal("a Polling client not seen for the window is alive")
	}
	if !(clientLiveness{conn: openPeer{alive: true}, heard: never}).alive() {
		t.Fatal("a client whose QUIC conn is open is not alive")
	}
	if (clientLiveness{conn: openPeer{}, heard: never}).alive() {
		t.Fatal("a client whose QUIC conn has closed is alive")
	}
	relaySide, client := tcpPair(t)
	t.Cleanup(func() { relaySide.Close(); client.Close() })
	relayClientActiveWindowNs.Store(int64(5 * time.Second))
	// The kernel keepalive at 1 s on both ends, and looks past several of
	// its probes. The ACK of a probe refreshes tcpi_last_ack_recv - the
	// control below shows it - and the rule built on that kept every socket
	// still up alive (P2-1 of the round-10 review). The probes acknowledge
	// no new data, so acknowledged bytes stay put.
	for _, c := range []net.Conn{relaySide, client} {
		if err := c.(*net.TCPConn).SetKeepAliveConfig(net.KeepAliveConfig{Enable: true,
			Idle: time.Second, Interval: time.Second, Count: 9}); err != nil {
			t.Fatal(err)
		}
	}
	go func() { _, _ = io.Copy(io.Discard, client) }()
	acks := &ackProgress{}
	live := clientLiveness{conn: relaySide, heard: never, acks: acks}
	if live.alive() {
		t.Fatal("a TCP that has acknowledged nothing yet is alive")
	}
	time.Sleep(2500 * time.Millisecond)
	if d := lastAckRecv(t, relaySide); d >= 1500*time.Millisecond {
		t.Fatalf("last ACK %v ago after 2.5 s of 1 s keepalives - the probes did not go out, the test proves nothing", d)
	}
	if live.alive() {
		t.Fatal("a TCP that acknowledged only keepalive probes is alive")
	}
	if _, err := relaySide.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if !live.alive() {
		t.Fatal("a TCP that acknowledged data 50 ms ago is not alive")
	}
}

// lastAckRecv reads tcpi_last_ack_recv off c.
func lastAckRecv(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var d time.Duration
	_ = raw.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			d = time.Duration(info.Last_ack_recv) * time.Millisecond
		}
	})
	return d
}

// openPeer is a conn that says whether its peer is there, as a QUIC conn does.
type openPeer struct {
	net.Conn
	alive bool
}

func (p openPeer) PeerAlive() bool { return p.alive }
