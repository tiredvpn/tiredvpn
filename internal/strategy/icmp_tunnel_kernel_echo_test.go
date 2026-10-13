package strategy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpFakePacket is one datagram queued for the client's raw socket.
type icmpFakePacket struct {
	data []byte
	from net.Addr
}

// icmpFakeNet stands in for the raw ICMP socket and everything behind it: the
// server host's kernel and the tiredvpn ICMP server. Every Echo Request the
// client writes is answered the way a Linux host with the default
// net.ipv4.icmp_echo_ignore_all=0 answers it - the kernel reflects the request
// payload in an Echo Reply first, the tunnel server's own reply follows - so
// the client sees its own c2s ciphertext before the reply it waits for.
type icmpFakeNet struct {
	serverIP   *net.IPAddr
	masterKey  []byte
	kernelEcho bool
	// echoData makes the fake server send every data payload back as an s2c
	// data reply, the way a peer that answers each frame would.
	echoData bool
	// noServer leaves only the kernel: the host has no tunnel server for us.
	noServer bool
	// foreignFirst delivers a reflection of every request from another host
	// ahead of everything else, as a raw socket sees unrelated ICMP.
	foreignFirst bool
	// forgedFirst delivers, from the server's address, a well-formed s2c
	// reply for the request's session sealed with the wrong key, ahead of
	// everything else: one spoofed packet that must not end the handshake.
	forgedFirst bool
	// reflectAgainAfter, if set, delivers the kernel's reflection a second
	// time that long after the first, as a network that duplicates packets does.
	reflectAgainAfter time.Duration
	// cancelOnRead, if set, is called when the first packet is read, and the
	// read then waits for the context's AfterFunc before returning it: the
	// context ends between ReadFrom and whatever the caller does next.
	cancelOnRead context.CancelFunc

	in     chan icmpFakePacket
	closed chan struct{}
	once   sync.Once

	mu           sync.Mutex
	readDeadline time.Time
	deadlineSet  chan struct{} // closed and replaced on every SetReadDeadline
	s2cSeq       uint32
	dataFrames   [][]byte // decrypted c2s data payloads, one per Echo Request
	sent         []icmpFakeSent
	afterClose   int // writes attempted after Close
}

// icmpFakeSent is one Echo Request as it left the client.
type icmpFakeSent struct {
	at    time.Time
	ipLen int // the IPv4 packet length the request would have on the wire
}

var icmpForeignHost = &net.IPAddr{IP: net.IPv4(198, 51, 100, 7)}

func newICMPFakeNet(secret []byte, kernelEcho bool) *icmpFakeNet {
	return &icmpFakeNet{
		serverIP:    &net.IPAddr{IP: net.IPv4(192, 0, 2, 10)},
		masterKey:   DeriveICMPKey(secret),
		kernelEcho:  kernelEcho,
		in:          make(chan icmpFakePacket, 4096),
		closed:      make(chan struct{}),
		deadlineSet: make(chan struct{}),
	}
}

// ReadFrom honours a read deadline moved while it blocks, as a socket does.
func (f *icmpFakeNet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		deadline, moved := f.readDeadline, f.deadlineSet
		f.mu.Unlock()
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timeout = time.After(time.Until(deadline))
		}
		select {
		case p := <-f.in:
			f.mu.Lock()
			cancel := f.cancelOnRead
			f.cancelOnRead = nil
			f.mu.Unlock()
			if cancel != nil {
				cancel()
				time.Sleep(50 * time.Millisecond)
			}
			return copy(b, p.data), p.from, nil
		case <-f.closed:
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-moved:
		}
	}
}

func (f *icmpFakeNet) WriteTo(b []byte, addr net.Addr) (int, error) {
	msg, err := icmp.ParseMessage(1, b)
	if err != nil {
		return 0, err
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if msg.Type != ipv4.ICMPTypeEcho || !ok {
		return len(b), nil
	}
	select {
	case <-f.closed:
		f.mu.Lock()
		f.afterClose++
		f.mu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	f.mu.Lock()
	f.sent = append(f.sent, icmpFakeSent{at: time.Now(), ipLen: 20 + len(b)})
	f.mu.Unlock()
	if f.forgedFirst && len(echo.Data) >= TunnelHeaderSize {
		header := ParseTunnelHeader(echo.Data[:TunnelHeaderSize])
		forged := icmpServerReply(DeriveICMPKey([]byte("attacker")), header.SessionID, echo.ID, header.PacketSeq, []byte("forged"), header.Flags)
		f.deliver(forged)
	}
	if f.foreignFirst {
		f.deliverFrom(icmpForeignHost, &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: bytes.Clone(echo.Data)},
		})
	}
	if f.kernelEcho {
		reflection := &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: bytes.Clone(echo.Data)},
		}
		f.deliver(reflection)
		if f.reflectAgainAfter > 0 {
			time.AfterFunc(f.reflectAgainAfter, func() { f.deliver(reflection) })
		}
	}
	f.serve(echo)
	return len(b), nil
}

// serve plays the tunnel server: authenticate the request with the c2s key,
// answer control packets, record data payloads.
func (f *icmpFakeNet) serve(echo *icmp.Echo) {
	if f.noServer || len(echo.Data) < TunnelHeaderSize {
		return
	}
	header := ParseTunnelHeader(echo.Data[:TunnelHeaderSize])
	c2s, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(f.masterKey, header.SessionID, "c2s"))
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], header.SessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(header.PacketSeq))
	plaintext, err := c2s.Open(nil, nonce, echo.Data[TunnelHeaderSize:], echo.Data[:TunnelHeaderSize])
	if err != nil {
		return
	}
	if header.Flags&FlagControl != 0 {
		f.reply(header.SessionID, echo.ID, plaintext, FlagControl)
		return
	}
	f.mu.Lock()
	f.dataFrames = append(f.dataFrames, plaintext)
	f.mu.Unlock()
	if f.echoData {
		f.reply(header.SessionID, echo.ID, plaintext, 0)
	}
}

// reply sends an s2c Echo Reply exactly as server/icmp_server.go sendEchoReply builds it.
func (f *icmpFakeNet) reply(sessionID uint32, id int, data []byte, flags uint8) {
	f.mu.Lock()
	f.s2cSeq++
	seq := f.s2cSeq
	f.mu.Unlock()
	f.deliver(icmpServerReply(f.masterKey, sessionID, id, seq, data, flags))
}

func icmpServerReply(masterKey []byte, sessionID uint32, id int, seq uint32, data []byte, flags uint8) *icmp.Message {
	s2c, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "s2c"))
	headerBytes := SerializeTunnelHeader(TunnelHeader{
		Magic:      ICMPTunnelMagic,
		Version:    ICMPTunnelVersion,
		Flags:      flags,
		SessionID:  sessionID,
		PacketSeq:  seq,
		PayloadLen: uint16(len(data)),
	})
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint32(nonce[0:], sessionID)
	binary.BigEndian.PutUint64(nonce[16:], uint64(seq))
	payload := append(bytes.Clone(headerBytes), s2c.Seal(nil, nonce, data, headerBytes)...)
	return &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: id, Seq: int(seq & 0xffff), Data: payload},
	}
}

func (f *icmpFakeNet) deliver(msg *icmp.Message) { f.deliverFrom(f.serverIP, msg) }

func (f *icmpFakeNet) deliverFrom(from net.Addr, msg *icmp.Message) {
	raw, err := msg.Marshal(nil)
	if err != nil {
		panic(err)
	}
	select {
	case f.in <- icmpFakePacket{data: raw, from: from}:
	case <-f.closed:
	}
}

func (f *icmpFakeNet) frames() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.dataFrames...)
}

func (f *icmpFakeNet) sends() []icmpFakeSent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]icmpFakeSent(nil), f.sent...)
}

func (f *icmpFakeNet) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *icmpFakeNet) LocalAddr() net.Addr { return &net.IPAddr{IP: net.IPv4(192, 0, 2, 20)} }

func (f *icmpFakeNet) SetDeadline(t time.Time) error { return f.SetReadDeadline(t) }

func (f *icmpFakeNet) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	close(f.deadlineSet)
	f.deadlineSet = make(chan struct{})
	f.mu.Unlock()
	return nil
}

func (f *icmpFakeNet) SetWriteDeadline(time.Time) error { return nil }

// icmpUseFakeNet routes Connect's raw socket to fake for the test's lifetime.
func icmpUseFakeNet(t *testing.T, fake *icmpFakeNet) {
	t.Helper()
	orig := icmpListenPacket
	icmpListenPacket = func(string, string) (net.PacketConn, error) { return fake, nil }
	t.Cleanup(func() { icmpListenPacket = orig })
}

func icmpConnect(t *testing.T, secret []byte, fake *icmpFakeNet) net.Conn {
	t.Helper()
	conn, _, err := icmpDial(t, t.Context(), secret, fake, 5*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return conn
}

// icmpDial runs Connect against fake and fails the test if it has not
// returned within limit, so a broken wait shows up as a failure and not as a
// test binary hung until go test's own timeout.
func icmpDial(t *testing.T, ctx context.Context, secret []byte, fake *icmpFakeNet, limit time.Duration) (net.Conn, time.Duration, error) {
	t.Helper()
	icmpUseFakeNet(t, fake)
	s := NewICMPTunnelStrategy(fake.serverIP.String()+":443", secret)
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		conn, err := s.Connect(ctx, fake.serverIP.String()+":443")
		done <- result{conn, err}
	}()
	select {
	case r := <-done:
		if r.conn != nil {
			t.Cleanup(func() { r.conn.Close() })
		}
		return r.conn, time.Since(start), r.err
	case <-time.After(limit):
		fake.Close()
		t.Fatalf("Connect still running after %v", limit)
		return nil, 0, nil
	}
}

// With the default icmp_echo_ignore_all=0 the server host's kernel answers the
// handshake Echo Request before the tunnel server does. Connect has to wait
// past that reflection for the server's authenticated reply.
func TestICMPConnectSkipsKernelEchoInHandshake(t *testing.T) {
	secret := []byte("icmp-kernel-echo-secret")
	fake := newICMPFakeNet(secret, true)
	icmpConnect(t, secret, fake)
}

// The same reflection arrives for every data packet. recvLoop must hand the
// reader only what the server sealed with the s2c key, never the client's own
// c2s ciphertext coming back.
func TestICMPReadSkipsKernelEchoOfDataPackets(t *testing.T) {
	secret := []byte("icmp-kernel-echo-secret")
	fake := newICMPFakeNet(secret, true)
	fake.echoData = true
	conn := icmpConnect(t, secret, fake)

	frame := []byte("\x00\x00\x00\x05hello")
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 0, len(frame))
	buf := make([]byte, 1500)
	for len(got) < len(frame) {
		n, err := icmpReadWithTimeout(conn, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("Read after %q: %v", got, err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("read %x, want the server's s2c payload %x", got, frame)
	}
	if n, err := icmpReadWithTimeout(conn, buf, 300*time.Millisecond); err == nil {
		t.Fatalf("read %d extra bytes %x: the kernel echo leaked into the stream", n, buf[:n])
	}
}

// icmpReadWithTimeout bounds a Read: icmpTunnelConn.Read blocks on its queue
// and does not honour read deadlines.
func icmpReadWithTimeout(conn net.Conn, buf []byte, d time.Duration) (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := conn.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(d):
		return 0, os.ErrDeadlineExceeded
	}
}

func icmpWaitFrames(t *testing.T, fake *icmpFakeNet, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f := fake.frames(); len(f) >= want {
			return f
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server saw %d data packets, want %d", len(fake.frames()), want)
	return nil
}

// The TUN layer writes one frame per Write, and a full-size frame (MTU 1280 +
// 4-byte length) is what Auto-MTU probes and bulk TCP put on the link. Cut into
// 40-byte pieces at 10 packets per second, one such frame took over three
// seconds of uplink, the probes alone filled the budget and everything behind
// them queued for ten seconds and more. A frame has to leave as one packet.
func TestICMPWriteSendsFullFrameInOnePacket(t *testing.T) {
	secret := []byte("icmp-frame-secret")
	fake := newICMPFakeNet(secret, false)
	conn := icmpConnect(t, secret, fake)

	frame := make([]byte, 4+1280)
	binary.BigEndian.PutUint32(frame, 1280)
	for i := range frame[4:] {
		frame[4+i] = byte(i)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first := icmpWaitFrames(t, fake, 1)[0]
	if !bytes.Equal(first, frame) {
		t.Fatalf("first data packet carried %d bytes, want the whole %d-byte frame", len(first), len(frame))
	}
}

// Small frames queued behind the rate limiter - TCP ACKs during a download -
// share one packet instead of each waiting for its own 100 ms slot.
func TestICMPSendLoopCoalescesQueuedFrames(t *testing.T) {
	secret := []byte("icmp-coalesce-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, StealthPacketRate)

	// Queue the frames before the send loop runs, as they pile up while it
	// sleeps out the rate limit.
	var want []byte
	for i := range 10 {
		frame := bytes.Repeat([]byte{byte(i)}, 56)
		if _, err := c.Write(frame); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want = append(want, frame...)
	}
	go c.sendLoop()

	first := icmpWaitFrames(t, fake, 1)[0]
	if !bytes.Equal(first, want) {
		t.Fatalf("first packet carried %d bytes, want all %d queued bytes in order", len(first), len(want))
	}
}

// Coalescing must keep each Write whole and in order: a write that does not
// fit what is already in the packet starts the next packet, and later small
// writes do not jump ahead of it. Losing a packet then loses whole frames, and
// the length-prefixed stream stays aligned and ordered.
func TestICMPSendLoopKeepsFramesWholeAndInOrder(t *testing.T) {
	secret := []byte("icmp-coalesce-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)

	writes := [][]byte{
		bytes.Repeat([]byte{1}, 100),
		bytes.Repeat([]byte{2}, MaxPayloadSize-50),
		bytes.Repeat([]byte{3}, 50),
	}
	for _, w := range writes {
		if _, err := c.Write(w); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	go c.sendLoop()

	got := icmpWaitFrames(t, fake, 2)
	want := [][]byte{writes[0], append(bytes.Clone(writes[1]), writes[2]...)}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d carried %d bytes starting %x, want %d starting %x",
				i, len(got[i]), got[i][:1], len(want[i]), want[i][:1])
		}
	}
}

// The TUN layer reuses its buffer for the next packet as soon as Write
// returns. What goes on the wire must be what was written, not whatever the
// buffer holds by the time the send loop gets to it.
func TestICMPWriteCopiesCallerBuffer(t *testing.T) {
	secret := []byte("icmp-copy-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)

	buf := bytes.Repeat([]byte{0xaa}, 200)
	want := bytes.Clone(buf)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for i := range buf {
		buf[i] = 0x55
	}
	go c.sendLoop()

	if got := icmpWaitFrames(t, fake, 1)[0]; !bytes.Equal(got, want) {
		t.Fatalf("packet carried %x..., want the bytes as written %x...", got[:4], want[:4])
	}
}

// The packet rate cap is the one stealth property the send loop keeps, so it
// is checked on the wire: with a full queue, including writes that wait as
// carry for the next packet, no two requests leave closer than 1/rate.
func TestICMPSendLoopHonoursRateLimit(t *testing.T) {
	secret := []byte("icmp-rate-secret")
	fake := newICMPFakeNet(secret, false)
	const rate = 20
	c := icmpSendConn(t, fake, secret, rate)
	for range 5 {
		// Each write fills most of a packet, so every packet after the first
		// starts from the carry of the one before.
		if _, err := c.Write(bytes.Repeat([]byte{1}, MaxPayloadSize-100)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	go c.sendLoop()

	icmpWaitFrames(t, fake, 5)
	sent := fake.sends()
	interval := time.Second / rate
	for i := 1; i < len(sent); i++ {
		if gap := sent[i].at.Sub(sent[i-1].at); gap < interval*9/10 {
			t.Fatalf("request %d left %v after the previous one, want at least %v", i, gap, interval)
		}
	}
}

// A write still waiting as carry when the conn is closed is dropped, not sent
// into the closed socket.
func TestICMPSendLoopStopsAfterClose(t *testing.T) {
	secret := []byte("icmp-close-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 5)
	for range 2 {
		if _, err := c.Write(bytes.Repeat([]byte{1}, MaxPayloadSize-100)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	go c.sendLoop()
	icmpWaitFrames(t, fake, 1)
	c.Close()
	fake.Close()
	time.Sleep(400 * time.Millisecond) // two rate-limit intervals
	fake.mu.Lock()
	after := fake.afterClose
	fake.mu.Unlock()
	if after != 0 {
		t.Fatalf("send loop wrote %d packets after Close", after)
	}
}

// recvLoop on its own, without the handshake in front of it: the kernel's
// reflection of a data request arrives first and the server's reply second.
// Only the reply may reach the reader.
func TestICMPRecvLoopDropsReflectedRequest(t *testing.T) {
	secret := []byte("icmp-recvloop-secret")
	fake := newICMPFakeNet(secret, true)
	masterKey := DeriveICMPKey(secret)
	const sessionID = 0x11223344
	sendCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "c2s"))
	recvCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(masterKey, sessionID, "s2c"))
	c := &icmpTunnelConn{
		icmpConn:   fake,
		serverIP:   fake.serverIP,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
		sessionID:  sessionID,
		tunnelID:   7,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
		rateLimit:  StealthPacketRate,
	}
	t.Cleanup(func() { c.Close() })
	go c.recvLoop()

	request, err := c.buildPacket([]byte("uplink frame"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// What the kernel sends back for that request: the same bytes as a reply.
	reflected, _ := icmp.ParseMessage(1, request)
	reflected.Type = ipv4.ICMPTypeEchoReply
	fake.deliver(reflected)
	want := []byte("downlink frame")
	fake.deliver(icmpServerReply(masterKey, sessionID, 7, 1, want, 0))

	buf := make([]byte, 1500)
	n, err := icmpReadWithTimeout(c, buf, 2*time.Second)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("read %q, want %q", buf[:n], want)
	}
}

// A raw socket also sees ICMP from hosts that have nothing to do with us. A
// packet from another address ahead of the server's reply must not end the
// handshake.
func TestICMPConnectSkipsPacketsFromOtherHosts(t *testing.T) {
	secret := []byte("icmp-foreign-secret")
	fake := newICMPFakeNet(secret, false)
	fake.foreignFirst = true
	icmpConnect(t, secret, fake)
}

// A spoofed packet with the server's address and our session that fails
// authentication is skipped like the kernel's reflection; otherwise one
// forged packet per attempt would keep the tunnel from ever coming up.
func TestICMPConnectSkipsForgedServerReply(t *testing.T) {
	secret := []byte("icmp-forged-secret")
	fake := newICMPFakeNet(secret, true)
	fake.forgedFirst = true
	icmpConnect(t, secret, fake)
}

// A server host that answers ping but runs no tunnel server for us (no
// -enable-icmp, or another secret) has to fail fast and as an answer, not as
// silence: the scan counts timeouts against the address, and this one talks.
// The error must not blame the secret either, a kernel reflection says
// nothing about it.
func TestICMPHandshakeReportsPingOnlyHost(t *testing.T) {
	orig := icmpTunnelReplyGrace
	icmpTunnelReplyGrace = 200 * time.Millisecond
	t.Cleanup(func() { icmpTunnelReplyGrace = orig })

	secret := []byte("icmp-ping-only-secret")
	fake := newICMPFakeNet(secret, true)
	fake.noServer = true
	conn, elapsed, err := icmpDial(t, t.Context(), secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded on kernel echoes alone")
	}
	if !errors.Is(err, errICMPNoTunnelReply) {
		t.Fatalf("err = %v, want errICMPNoTunnelReply", err)
	}
	if isTimeoutError(err) {
		t.Fatalf("err = %v is classified as a timeout; the host answered", err)
	}
	if strings.Contains(err.Error(), "auth") {
		t.Fatalf("err = %v blames authentication", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Connect took %v, want about the %v grace", elapsed, icmpTunnelReplyGrace)
	}
}

// With nothing coming back at all the failure stays a timeout: that is the
// silence the scan is meant to count.
func TestICMPHandshakeSilenceIsTimeout(t *testing.T) {
	secret := []byte("icmp-silence-secret")
	fake := newICMPFakeNet(secret, false)
	fake.noServer = true
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	conn, _, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no reply")
	}
	if !isTimeoutError(err) {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

// Cancelling the caller's context ends the handshake wait at once rather than
// at Connect's own 10-second deadline, and says it was cancelled.
func TestICMPHandshakeStopsOnCancel(t *testing.T) {
	secret := []byte("icmp-cancel-secret")
	fake := newICMPFakeNet(secret, false)
	fake.noServer = true
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)
	conn, elapsed, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no reply")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Connect returned %v after cancel, want it to stop with the context", elapsed)
	}
}

// The handshake init is a packet like any other: the first data packet must
// not follow it inside the rate limit's interval.
func TestICMPHandshakeInitCountsAgainstRateLimit(t *testing.T) {
	secret := []byte("icmp-init-rate-secret")
	fake := newICMPFakeNet(secret, false)
	conn := icmpConnect(t, secret, fake)
	if _, err := conn.Write([]byte("first frame")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	icmpWaitFrames(t, fake, 1)
	sent := fake.sends()
	if len(sent) < 2 {
		t.Fatalf("saw %d requests, want init and a data packet", len(sent))
	}
	interval := time.Second / StealthPacketRate
	if gap := sent[1].at.Sub(sent[0].at); gap < interval*9/10 {
		t.Fatalf("data packet left %v after the init, want at least %v", gap, interval)
	}
}

// icmpSendConn builds a tunnel conn for send-path tests without a handshake;
// the send loop is not started.
func icmpSendConn(t *testing.T, fake *icmpFakeNet, secret []byte, rateLimit int) *icmpTunnelConn {
	t.Helper()
	const sessionID = 0x05060708
	sendCipher, _ := chacha20poly1305.NewX(DeriveICMPDirectionalKey(DeriveICMPKey(secret), sessionID, "c2s"))
	c := &icmpTunnelConn{
		icmpConn:   fake,
		serverIP:   fake.serverIP,
		sendCipher: sendCipher,
		sessionID:  sessionID,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		done:       make(chan struct{}),
		rateLimit:  rateLimit,
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// On a path narrower than our largest packet (a 1280-MTU tunnel underneath,
// some mobile APNs) no request may be larger than the path: the kernel would
// fragment it, and a fragmented echo request is a mark on the wire. A full
// TUN frame is cut across packets instead, and the stream stays in order.
func TestICMPSendLoopKeepsPacketsWithinPathMTU(t *testing.T) {
	secret := []byte("icmp-pmtu-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)
	const pathMTU = 1300
	c.pathMTU = func() int { return pathMTU }

	frame := bytes.Repeat([]byte{7}, 4+1280)
	var want []byte
	for _, w := range [][]byte{frame, bytes.Repeat([]byte{8}, 56), bytes.Repeat([]byte{9}, 56)} {
		if _, err := c.Write(w); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want = append(want, w...)
	}
	go c.sendLoop()

	var got []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		got = bytes.Join(fake.frames(), nil)
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream carried %d bytes, want the %d written, in order", len(got), len(want))
	}
	for i, s := range fake.sends() {
		if s.ipLen > pathMTU {
			t.Fatalf("request %d is %d bytes on the wire, path MTU is %d", i, s.ipLen, pathMTU)
		}
	}
}

// A path MTU below the IPv4 minimum is not believed.
func TestICMPPacketPayloadLimitFloor(t *testing.T) {
	c := &icmpTunnelConn{pathMTU: func() int { return 100 }}
	if got, want := c.packetPayloadLimit(), icmpMinPathMTU-icmpPacketOverhead; got != want {
		t.Fatalf("limit = %d, want %d", got, want)
	}
	c.pathMTU = func() int { return 0 }
	if got := c.packetPayloadLimit(); got != MaxPayloadSize {
		t.Fatalf("limit with unknown MTU = %d, want MaxPayloadSize %d", got, MaxPayloadSize)
	}
}

// When the path is too narrow for a full frame, every frame is cut. The tail
// of a cut frame must share its packet with the bytes that follow; alone it
// spends a rate-limited slot on a few dozen bytes, and the bench measured the
// uplink halving that way.
func TestICMPSendLoopFillsPacketsAfterACut(t *testing.T) {
	secret := []byte("icmp-fill-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)
	const pathMTU = 1300
	c.pathMTU = func() int { return pathMTU }

	var want []byte
	for i := range 6 {
		frame := bytes.Repeat([]byte{byte(i + 1)}, 4+1280)
		if _, err := c.Write(frame); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want = append(want, frame...)
	}
	go c.sendLoop()

	limit := pathMTU - icmpPacketOverhead
	packets := (len(want) + limit - 1) / limit
	got := bytes.Join(icmpWaitFrames(t, fake, packets), nil)
	time.Sleep(50 * time.Millisecond) // let any extra packet show up
	if n := len(fake.frames()); n != packets {
		t.Fatalf("%d bytes took %d packets, want %d full ones", len(want), n, packets)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream carried %d bytes, want the %d written, in order", len(got), len(want))
	}
}

// icmpShortGrace shortens the wait after the kernel's reflection for a test.
func icmpShortGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := icmpTunnelReplyGrace
	icmpTunnelReplyGrace = d
	t.Cleanup(func() { icmpTunnelReplyGrace = orig })
}

// The ping-only verdict is about the server host. A copy of our init coming
// back from some other address says nothing about it; with the server silent
// the result must stay a timeout.
func TestICMPForeignReflectionDoesNotCountAsServer(t *testing.T) {
	icmpShortGrace(t, 200*time.Millisecond)
	secret := []byte("icmp-foreign-reflection-secret")
	fake := newICMPFakeNet(secret, false)
	fake.noServer = true
	fake.foreignFirst = true
	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
	defer cancel()
	conn, _, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no server")
	}
	if errors.Is(err, errICMPNoTunnelReply) || !isTimeoutError(err) {
		t.Fatalf("err = %v, want a timeout: only another host echoed the init", err)
	}
}

// Cancelling while the handshake waits out the window after the reflection
// is a cancellation, not a ping-only host.
func TestICMPHandshakeCancelInsideReflectionWindow(t *testing.T) {
	icmpShortGrace(t, 2*time.Second)
	secret := []byte("icmp-window-cancel-secret")
	fake := newICMPFakeNet(secret, true)
	fake.noServer = true
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)
	conn, elapsed, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no server")
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, errICMPNoTunnelReply) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Connect returned %v after a cancel at 200ms", elapsed)
	}
}

// The window starts at the first reflection. A duplicate of it arriving later
// must not restart the wait.
func TestICMPHandshakeWindowStartsAtFirstReflection(t *testing.T) {
	icmpShortGrace(t, 400*time.Millisecond)
	secret := []byte("icmp-dup-reflection-secret")
	fake := newICMPFakeNet(secret, true)
	fake.noServer = true
	fake.reflectAgainAfter = 300 * time.Millisecond
	conn, elapsed, err := icmpDial(t, t.Context(), secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no server")
	}
	if !errors.Is(err, errICMPNoTunnelReply) {
		t.Fatalf("err = %v, want errICMPNoTunnelReply", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("Connect took %v, want about the 400ms window from the first reflection", elapsed)
	}
}

// A queued write that exactly fills what a cut tail leaves of the packet must
// not leave an empty remainder behind: that would send a request with no data
// and spend a rate-limited slot on it.
func TestICMPSendLoopExactFillLeavesNoEmptyPacket(t *testing.T) {
	secret := []byte("icmp-exact-fill-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)
	const pathMTU = 1300
	c.pathMTU = func() int { return pathMTU }
	limit := pathMTU - icmpPacketOverhead

	first := bytes.Repeat([]byte{1}, limit+10)  // cut: limit, then a 10-byte tail
	second := bytes.Repeat([]byte{2}, limit-10) // fills the tail's packet exactly
	for _, w := range [][]byte{first, second} {
		if _, err := c.Write(w); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	go c.sendLoop()

	icmpWaitFrames(t, fake, 2)
	time.Sleep(50 * time.Millisecond) // let a third packet show up if there is one
	got := fake.frames()
	if len(got) != 2 {
		sizes := make([]int, len(got))
		for i, f := range got {
			sizes[i] = len(f)
		}
		t.Fatalf("sent %d packets with %v bytes of data, want 2 full ones", len(got), sizes)
	}
}

// The path can narrow during a session (Fragmentation Needed). Packets after
// that must follow the new MTU, not the one seen when the conn started.
func TestICMPSendLoopFollowsPathMTUChange(t *testing.T) {
	secret := []byte("icmp-pmtu-change-secret")
	fake := newICMPFakeNet(secret, false)
	c := icmpSendConn(t, fake, secret, 1000)
	var calls atomic.Int32
	c.pathMTU = func() int {
		if calls.Add(1) == 1 {
			return 1500
		}
		return 1300
	}

	var want []byte
	for i := range 4 {
		frame := bytes.Repeat([]byte{byte(i + 1)}, 4+1280)
		if _, err := c.Write(frame); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want = append(want, frame...)
	}
	go c.sendLoop()

	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for len(got) < len(want) && time.Now().Before(deadline) {
		got = bytes.Join(fake.frames(), nil)
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream carried %d bytes, want the %d written, in order", len(got), len(want))
	}
	sent := fake.sends()
	for i, s := range sent[1:] {
		if s.ipLen > 1300 {
			t.Fatalf("request %d is %d bytes after the path narrowed to 1300", i+1, s.ipLen)
		}
	}
}

// The same through Connect: the conn it builds has to ask the kernel for the
// path MTU again for later packets, not keep the answer from the start.
func TestICMPConnectRereadsPathMTU(t *testing.T) {
	var calls atomic.Int32
	orig := icmpPathMTU
	icmpPathMTU = func(net.IP) int {
		if calls.Add(1) == 1 {
			return 1500
		}
		return 1300
	}
	t.Cleanup(func() { icmpPathMTU = orig })

	secret := []byte("icmp-connect-pmtu-secret")
	fake := newICMPFakeNet(secret, false)
	conn := icmpConnect(t, secret, fake)
	for i := range 3 {
		if _, err := conn.Write(bytes.Repeat([]byte{byte(i + 1)}, 4+1280)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	icmpWaitFrames(t, fake, 3)
	sent := fake.sends() // [0] is the handshake init
	for i, s := range sent[2:] {
		if s.ipLen > 1300 {
			t.Fatalf("data request %d is %d bytes after the path narrowed to 1300", i+2, s.ipLen)
		}
	}
}

// A Connect deadline shorter than the window after the reflection ends the
// wait at the deadline.
func TestICMPHandshakeWindowEndsAtDeadline(t *testing.T) {
	icmpShortGrace(t, 3*time.Second)
	secret := []byte("icmp-window-deadline-secret")
	fake := newICMPFakeNet(secret, true)
	fake.noServer = true
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	conn, elapsed, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no server")
	}
	if elapsed > time.Second {
		t.Fatalf("Connect took %v with a 300ms deadline", elapsed)
	}
}

// The context can end while the handshake is between ReadFrom returning the
// reflection and arming the window. The AfterFunc has moved the deadline into
// the past by then; arming the window must not move it out again.
func TestICMPHandshakeContextEndingAtTheReflection(t *testing.T) {
	icmpShortGrace(t, 3*time.Second)
	secret := []byte("icmp-window-race-secret")
	fake := newICMPFakeNet(secret, true)
	fake.noServer = true
	ctx, cancel := context.WithCancel(t.Context())
	fake.cancelOnRead = cancel
	conn, elapsed, err := icmpDial(t, ctx, secret, fake, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("Connect succeeded with no server")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Connect took %v after the context ended at the first read", elapsed)
	}
}
