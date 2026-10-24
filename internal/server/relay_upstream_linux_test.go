package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// P1-1 of the round-8 review: the read path of the relay's upstream stego
// conn set a write deadline of 10 s for its WINDOW_UPDATE flush and left it
// behind. The relay's TUN bridge and its proxy relays write upstream without
// a deadline of their own, so the first write up more than 10 s after a
// download failed, and tls.Conn made the failure permanent. The exit then
// read "bad record MAC" at the close. These run the real relay paths -
// relayTUNToUpstream and handleRawTunnel over UpstreamDialer - into a real
// exit, with the read path's deadline scaled 1:25.

// scaleReadPathWrite scales the stego read path's write deadline by legScale.
func scaleReadPathWrite(t *testing.T) time.Duration {
	t.Helper()
	d := 10 * time.Second / legScale
	old := strategy.SetStegoReadPathWriteTimeout(d)
	t.Cleanup(func() { strategy.SetStegoReadPathWriteTimeout(old) })
	return d
}

// captureLog sends the log to a buffer for the test.
func captureLog(t *testing.T) *lockedLog {
	t.Helper()
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return out
}

// relayBridge is a downstream client on a relay's TUN bridge to an exit.
type relayBridge struct {
	exit     *legExit
	client   net.Conn // the client's side, past the handshake response
	clientIP net.IP
	down     atomic.Int64  // packets that came down to the client
	done     chan struct{} // closed when relayTUNToUpstream returned
}

// startRelayBridge runs relayTUNToUpstream for a client over loopback TCP,
// its upstream an exit, and reads what comes down.
func startRelayBridge(t *testing.T) *relayBridge {
	t.Helper()
	secret := []byte("relay-leg-secret-0123456789abcdef")
	b := &relayBridge{exit: newLegExit(t, secret), done: make(chan struct{})}
	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(b.exit.addr, secret)}
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close() })
	go func() {
		defer close(b.done)
		relayTUNToUpstream(relaySide, relayCtx, testLogger(t), dialTUNHandshake())
	}()
	resp, conn, err := tun.ReadTUNHandshakeResponse(client, 0x04, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("the exit refused the tunnel: %x", resp)
	}
	b.client, b.clientIP = conn, net.IP(append([]byte(nil), resp[5:9]...))
	go func() {
		header := make([]byte, 4)
		buf := make([]byte, 2048)
		for {
			if _, err := io.ReadFull(b.client, header); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(header)
			if n == 0 {
				continue // the exit's keepalive echo
			}
			if _, err := io.ReadFull(b.client, buf[:n]); err != nil {
				return
			}
			b.down.Add(1)
		}
	}()
	return b
}

// send writes one [len:4][pkt:N] frame up, pkt nil for a keepalive.
func (b *relayBridge) send(pkt []byte) error {
	frame := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(frame, uint32(len(pkt)))
	copy(frame[4:], pkt)
	_, err := b.client.Write(frame)
	return err
}

// upPacket is a packet from the client's tunnel address.
func (b *relayBridge) upPacket() []byte {
	p := ipv4Packet(b.clientIP, net.IPv4(10, 8, 7, 9))
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

// alive fails the test if the relay ended the bridge.
func (b *relayBridge) alive(t *testing.T, out *lockedLog, when string) {
	t.Helper()
	select {
	case <-b.done:
		t.Fatalf("the relay closed the bridge %s:\n%s", when, out.String())
	default:
	}
}

// download streams 1200-byte packets from the exit to the client, one every
// every for span, and waits for them to come down.
func (b *relayBridge) download(t *testing.T, out *lockedLog, span, every time.Duration) {
	t.Helper()
	w := exitWriterFor(t, b.exit, b.clientIP)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), b.clientIP)
	pkt = append(pkt, make([]byte, 1200-len(pkt))...)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	var sent int64
	tick := time.NewTicker(every)
	defer tick.Stop()
	for end := time.Now().Add(span); time.Now().Before(end); {
		<-tick.C
		if w.SendPacket(pkt) == nil {
			sent++
		}
	}
	// The read path flushes WINDOW_UPDATE every 256 KB: the download has to
	// cross it for the test to mean anything.
	if sent*int64(len(pkt)) < 2*256*1024 {
		t.Fatalf("only %d packets went down, below two WINDOW_UPDATE flushes", sent)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.down.Load() < sent && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := b.down.Load(); got < sent {
		t.Fatalf("%d of %d packets came down", got, sent)
	}
	b.alive(t, out, "during the download")
}

// upArrives sends one packet up and waits for it on the exit's TUN.
func (b *relayBridge) upArrives(t *testing.T, out *lockedLog, when string) {
	t.Helper()
	before := b.exit.app.got.Load()
	if err := b.send(b.upPacket()); err != nil {
		t.Fatalf("client write: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.exit.app.got.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if b.exit.app.got.Load() == before {
		t.Fatalf("the packet sent up %s never reached the exit:\n%s", when, out.String())
	}
	b.alive(t, out, "after the packet up")
}

// closesCleanly hangs the client up and checks both ends saw a close: the
// relay names the client, and the exit reads a clean end of the stream, not
// a TLS record broken by a failed write.
func (b *relayBridge) closesCleanly(t *testing.T, out *lockedLog) {
	t.Helper()
	b.client.Close()
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay kept the bridge after the client hung up")
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.exit.ended.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	logs := out.String()
	if !strings.Contains(logs, "Relay TUN bridge closed") || !strings.Contains(logs, "): the client closed it") {
		t.Fatalf("the relay did not say the client closed the bridge:\n%s", logs)
	}
	if strings.Contains(logs, "bad record MAC") {
		t.Fatalf("the exit read a broken TLS record at the close:\n%s", logs)
	}
	if !strings.Contains(logs, "H2 TUN session ended: the peer closed it") {
		t.Fatalf("the exit did not see a clean close:\n%s", logs)
	}
}

// TestARelayBridgeWritesUpAfterAQuietDownload is the stand's shape: 1200 B
// down every 10 ms for 3 minutes, a quiet tail longer than the read path's
// write deadline, then one packet up - which failed on the relay and killed
// the bridge. Scaled 1:25 in time, the 10 ms pacing kept.
func TestARelayBridgeWritesUpAfterAQuietDownload(t *testing.T) {
	quiet := 2 * scaleReadPathWrite(t)
	out := captureLog(t)
	b := startRelayBridge(t)
	b.download(t, out, 3*time.Minute/legScale, 10*time.Millisecond)
	time.Sleep(quiet)
	b.upArrives(t, out, "after the quiet tail")
	b.closesCleanly(t, out)
}

// TestARelayBridgeCarriesKeepalivesAfterADownload: after a download the
// client sends only keepalives, on its 10 s grid scaled. The first one past
// the read path's deadline failed the same way.
func TestARelayBridgeCarriesKeepalivesAfterADownload(t *testing.T) {
	limit := scaleReadPathWrite(t)
	out := captureLog(t)
	b := startRelayBridge(t)
	b.download(t, out, 2*time.Second, time.Millisecond)
	every := 10 * time.Second / legScale
	for end := time.Now().Add(5 * limit); time.Now().Before(end); {
		time.Sleep(every)
		if err := b.send(nil); err != nil {
			t.Fatalf("client keepalive: %v", err)
		}
		// The relay copies a keepalive up at once; give it the time.
		time.Sleep(20 * time.Millisecond)
		b.alive(t, out, "on a keepalive")
	}
	if n := b.exit.ended.Load(); n != 0 {
		t.Fatalf("the exit ended the session:\n%s", out.String())
	}
	b.upArrives(t, out, "after the keepalives")
	b.closesCleanly(t, out)
}

// TestARelayProxyWritesUpAfterAQuietDownload is P1-1 on the proxy path:
// handleRawTunnel dials the target through UpstreamDialer.Dial and relays
// with optimizedRelay. 1 MiB comes down, the client is quiet past the read
// path's deadline, then sends "hello", which has to reach the target.
//
// The exit does not pass the target's hang-up on to its peer (a finding of
// its own, outside this fix): the relay learns the session is over when the
// exit's read deadline ends it, scaled here.
func TestARelayProxyWritesUpAfterAQuietDownload(t *testing.T) {
	quiet := 2 * scaleReadPathWrite(t)
	oldRead := h2FrameReadTimeoutNs.Load()
	h2FrameReadTimeoutNs.Store(oldRead / legScale)
	t.Cleanup(func() { h2FrameReadTimeoutNs.Store(oldRead) })
	out := captureLog(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	const size = 1 << 20
	hello := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := c.Write(make([]byte, size)); err != nil {
			return
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		hello <- got
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
	req := append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0x00 {
		t.Fatalf("relay ack %x: %v\n%s", ack, err, out.String())
	}
	if _, err := io.ReadFull(client, make([]byte, size)); err != nil {
		t.Fatalf("download: %v\n%s", err, out.String())
	}
	_ = client.SetReadDeadline(time.Time{})
	time.Sleep(quiet)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	select {
	case got := <-hello:
		if !bytes.Equal(got, []byte("hello")) {
			t.Fatalf("the target got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the write up after the quiet never reached the target:\n%s", out.String())
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(3 * h2FrameReadTimeout()):
		t.Fatal("the relay kept the tunnel past the exit's read deadline")
	}
	logs := out.String()
	if !strings.Contains(logs, "Tunnel closed (up=5, down=1048576): the client closed it") {
		t.Fatalf("the relay did not say the client closed the tunnel:\n%s", logs)
	}
	if strings.Contains(logs, "bad record MAC") {
		t.Fatalf("a TLS record broke at the close:\n%s", logs)
	}
}

// TestAStegoCloseAfterAFailedWriteEndsTheStream: a TLS write that failed
// spent a record number, so the close_notify the stego conn's Close sent
// after it read as "bad record MAC" at the peer. The peer has to read the
// end of the stream instead.
func TestAStegoCloseAfterAFailedWriteEndsTheStream(t *testing.T) {
	client, server := tlsLoopbackPair(t)
	t.Cleanup(func() { server.Close() })
	sc := strategy.NewHTTP2StegoConn(client, []byte("relay-leg-secret-0123456789abcdef"), true,
		strategy.NaivePaddingStandard, nil)
	_ = sc.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := sc.Write([]byte("lost")); err == nil {
		t.Fatal("a write past its deadline went through - the test cannot fail one")
	}
	_ = sc.SetWriteDeadline(time.Time{})
	sc.Close()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(server); err != nil {
		t.Fatalf("the peer read %v, want the end of the stream", err)
	}
}

// TestAStegoWritesAfterASettingsAckAndAQuiet: the read path's other write
// is the SETTINGS ack. Our exits send SETTINGS only in the handshake, which
// waitForServerAck answers, so no relay path reaches this one; a peer that
// sends SETTINGS mid-session does. A write after the ack and a quiet past
// the read path's deadline has to go through.
func TestAStegoWritesAfterASettingsAckAndAQuiet(t *testing.T) {
	quiet := 2 * scaleReadPathWrite(t)
	client, peer := tcpPair(t)
	t.Cleanup(func() { client.Close(); peer.Close() })
	sc := strategy.NewHTTP2StegoConn(client, []byte("relay-leg-secret-0123456789abcdef"), true,
		strategy.NaivePaddingStandard, nil)
	go func() { _, _ = sc.Read(make([]byte, 2048)) }()
	pf := http2.NewFramer(peer, peer)
	if err := pf.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := pf.ReadFrame()
	if err != nil {
		t.Fatalf("waiting for the SETTINGS ack: %v", err)
	}
	if s, ok := f.(*http2.SettingsFrame); !ok || !s.IsAck() {
		t.Fatalf("got %T, want the SETTINGS ack", f)
	}
	time.Sleep(quiet)
	if _, err := sc.Write([]byte("after the quiet")); err != nil {
		t.Fatalf("write after the SETTINGS ack and a quiet: %v", err)
	}
	if _, err := pf.ReadFrame(); err != nil {
		t.Fatalf("the peer got nothing: %v", err)
	}
}
