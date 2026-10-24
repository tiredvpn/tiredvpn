package strategy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// close is shutdown, under the name the pacer tests have always used.
func (p *writePacer) close() error { return p.shutdown() }

// setForTest replaces *v for the rest of the test.
func setForTest[T any](t *testing.T, v *T, x T) {
	t.Helper()
	old := *v
	*v = x
	t.Cleanup(func() { *v = old })
}

// parkingShaper cuts writes into 1200-byte frames like chunkShaper and
// paces them 50 ms apart, but its second NextDelay call blocks until
// release is closed. The pacer calls NextDelay after it has taken a frame
// and before it writes it, so a test can hold the pacer between frames,
// with the rest of the queue waiting, for as long as it needs.
type parkingShaper struct {
	chunkShaper
	calls   atomic.Int64
	parked  chan struct{}
	release chan struct{}
}

func newParkingShaper() *parkingShaper {
	return &parkingShaper{
		chunkShaper: chunkShaper{constShaper{delay: pacerMaxDelay}},
		parked:      make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (s *parkingShaper) NextDelay(d shaper.Direction) time.Duration {
	if s.calls.Add(1) == 2 {
		close(s.parked)
		<-s.release
	}
	return s.chunkShaper.NextDelay(d)
}

// testTLSConfigs returns a server config with a fresh self-signed
// certificate and a client config that trusts it.
func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "close.test"},
		DNSNames:     []string{"close.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}},
		&tls.Config{RootCAs: roots, ServerName: "close.test"}
}

// tcpPair returns both ends of a loopback TCP connection with small socket
// buffers, so a test can fill them quickly.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	c, s := cli.(*net.TCPConn), srv.(*net.TCPConn)
	_ = c.SetWriteBuffer(32 << 10)
	_ = s.SetReadBuffer(32 << 10)
	return c, s
}

// closeTransport is the conn a MorphedConn under test runs over, and the
// raw socket beneath it.
type closeTransport struct {
	name string
	dial func(t *testing.T) (conn net.Conn, raw *net.TCPConn)
}

// closeTransports are plain TCP and TLS over TCP, with a peer that reads
// nothing after the TLS handshake.
var closeTransports = []closeTransport{
	{"tcp", func(t *testing.T) (net.Conn, *net.TCPConn) {
		c, _ := tcpPair(t)
		return c, c
	}},
	{"tls", func(t *testing.T) (net.Conn, *net.TCPConn) {
		c, s := tcpPair(t)
		srvCfg, cliCfg := testTLSConfigs(t)
		srv := tls.Server(s, srvCfg)
		hs := make(chan error, 1)
		go func() { hs <- srv.Handshake() }()
		cli := tls.Client(c, cliCfg)
		if err := cli.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		if err := <-hs; err != nil {
			t.Fatalf("server handshake: %v", err)
		}
		return cli, c
	}},
}

// fillSendBuffer writes to raw until the kernel takes no more, so the next
// write on the connection blocks: what a peer that stopped reading looks
// like from the sender. The bytes go under any TLS layer; the peer never
// reads them. One timed-out write is not enough: the receiver can compact
// its queue and reopen the window by tens of KB a little later (seen under
// stress -c 20), so the buffer counts as full only after two writes in a
// row, each given longer than the 200 ms persist timer, take nothing.
func fillSendBuffer(t *testing.T, raw *net.TCPConn) {
	t.Helper()
	junk := make([]byte, 1<<20)
	idle := 0
	for range 200 {
		_ = raw.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := raw.Write(junk)
		if err != nil && !isTimeout(err) {
			t.Fatalf("filling the send buffer: %v", err)
		}
		if n > 0 {
			idle = 0
			continue
		}
		if idle++; idle == 2 {
			_ = raw.SetWriteDeadline(time.Time{})
			return
		}
	}
	t.Fatal("the send buffer never filled")
}

func isTimeout(err error) bool {
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

// parkedClient builds a shaped MorphedConn over conn, fills the send
// buffer, and queues a write that the pacer holds between its first and
// second frame: nothing is blocked in a write, the rest of the queue is
// waiting, and the next write cannot go out.
func parkedClient(t *testing.T, conn net.Conn, raw *net.TCPConn) (*MorphedConn, *parkingShaper) {
	t.Helper()
	sh := newParkingShaper()
	t.Cleanup(func() {
		select {
		case <-sh.release:
		default:
			close(sh.release)
		}
	})
	mc := &MorphedConn{Conn: conn, profile: &TrafficProfile{Name: "T"}, shaper: sh}
	// The TUN writer's per-packet deadline.
	_ = mc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := mc.Write(closeTestPayload(64 << 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-sh.parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the pacer never reached its second frame")
	}
	fillSendBuffer(t, raw)
	return mc, sh
}

// closeParked runs mc.Close, lets the pacer go on once Close has put its
// deadline on the conn, calls during (if set) in between, and returns what
// Close returned and how long it took. It fails the test if Close is still
// running after limit.
func closeParked(t *testing.T, mc *MorphedConn, sh *parkingShaper, during func(), limit time.Duration) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- mc.Close() }()
	select {
	case <-mc.pacer.done:
	case <-time.After(limit):
		t.Fatal("Close never stopped the pacer")
	}
	if during != nil {
		during()
	}
	close(sh.release)
	select {
	case err := <-closed:
		return time.Since(start), err
	case <-time.After(limit):
		t.Fatalf("Close still running after %v", limit)
		return 0, nil
	}
}

// TestMorphedConnCloseKeepsAbortDeadline is VPNClient.Stop: it sets an
// expired deadline and then calls Close, expecting the conn to go now.
// Close used to replace that deadline with its own 5 s one and drain the
// queue into a peer that does not read: 5.0 s instead of the 32-44 ms of
// the code before it. Over TLS the close_notify then cost another 5 s.
func TestMorphedConnCloseKeepsAbortDeadline(t *testing.T) {
	for _, tr := range closeTransports {
		t.Run(tr.name, func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetDeadline(time.Now())
			took, err := closeParked(t, mc, sh, nil, 20*time.Second)
			if took > time.Second {
				t.Fatalf("Close after an expired deadline took %v", took)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete for the queue it gave up", err)
			}
		})
	}
}

// TestMorphedConnCloseIgnoresLaterExtension: the TUN writer moves the
// write deadline 30 s out before every packet, and it may do so while
// Close runs. That must not push the close deadline out with it.
func TestMorphedConnCloseIgnoresLaterExtension(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 300*time.Millisecond)
	// Long enough that only the close deadline can end Close in time.
	setForTest(t, &closeAbortGrace, time.Minute)
	extensions := []struct {
		name   string
		extend func(mc *MorphedConn)
	}{
		{"SetWriteDeadline +30s", func(mc *MorphedConn) { _ = mc.SetWriteDeadline(time.Now().Add(30 * time.Second)) }},
		{"SetDeadline +30s", func(mc *MorphedConn) { _ = mc.SetDeadline(time.Now().Add(30 * time.Second)) }},
		{"SetWriteDeadline cleared", func(mc *MorphedConn) { _ = mc.SetWriteDeadline(time.Time{}) }},
	}
	for _, tr := range closeTransports {
		for _, ext := range extensions {
			t.Run(tr.name+", "+ext.name, func(t *testing.T) {
				conn, raw := tr.dial(t)
				mc, sh := parkedClient(t, conn, raw)
				took, err := closeParked(t, mc, sh, func() { ext.extend(mc) }, 20*time.Second)
				if took > pacerCloseTimeout+2*time.Second {
					t.Fatalf("Close took %v with a %v bound", took, pacerCloseTimeout)
				}
				if !errors.Is(err, ErrShaperCloseIncomplete) {
					t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
				}
			})
		}
	}
}

// TestMorphedConnCloseBoundOverTLS: with a peer that does not read and no
// deadline from the caller, Close takes pacerCloseTimeout over TLS too.
// It used to take twice that: once the drain gave up, tls.Conn.Close spent
// its own 5 s trying to send close_notify into the same full window.
func TestMorphedConnCloseBoundOverTLS(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 500*time.Millisecond)
	for _, tr := range closeTransports {
		t.Run(tr.name, func(t *testing.T) {
			conn, raw := tr.dial(t)
			mc, sh := parkedClient(t, conn, raw)
			_ = mc.SetWriteDeadline(time.Time{})
			took, err := closeParked(t, mc, sh, nil, 20*time.Second)
			if took > pacerCloseTimeout+2*time.Second {
				t.Fatalf("Close took %v with a %v bound", took, pacerCloseTimeout)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
			}
		})
	}
}

// errSockClose marks the socket's own Close error.
var errSockClose = errors.New("socket close failed")

// deafConn ignores every deadline and fails its Close with errSockClose,
// after closing the conn under it.
type deafConn struct{ net.Conn }

func (deafConn) SetDeadline(time.Time) error      { return nil }
func (deafConn) SetReadDeadline(time.Time) error  { return nil }
func (deafConn) SetWriteDeadline(time.Time) error { return nil }
func (c deafConn) Close() error {
	_ = c.Conn.Close()
	return errSockClose
}

// closeErrConn honours deadlines but fails its Close with errSockClose.
type closeErrConn struct{ net.Conn }

func (c closeErrConn) Close() error {
	_ = c.Conn.Close()
	return errSockClose
}

// TestMorphedConnCloseBoundedWithoutDeadlines: a conn whose write
// deadlines do nothing cannot be cut short by the close deadline, so a
// write blocked on a peer that does not read held Close forever. Close now
// closes the socket closeAbortGrace past the deadline, and still reports
// both the lost tail and the socket's error.
func TestMorphedConnCloseBoundedWithoutDeadlines(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 300*time.Millisecond)
	cli, srv := net.Pipe()
	defer srv.Close()
	mc := &MorphedConn{Conn: deafConn{cli}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	if _, err := mc.Write(closeTestPayload(64 << 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- mc.Close() }()
	select {
	case err := <-closed:
		if took := time.Since(start); took > pacerCloseTimeout+closeAbortGrace+2*time.Second {
			t.Errorf("Close took %v", took)
		}
		if !errors.Is(err, ErrShaperCloseIncomplete) || !errors.Is(err, errSockClose) {
			t.Fatalf("Close = %v, want ErrShaperCloseIncomplete joined with the socket's error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung on a conn that ignores write deadlines")
	}
}

// TestMorphedConnCloseJoinsSocketError: with the whole queue delivered,
// Close still reports the socket's own Close error.
func TestMorphedConnCloseJoinsSocketError(t *testing.T) {
	cli, srv := net.Pipe()
	defer srv.Close()
	go func() { _, _ = io.Copy(io.Discard, srv) }()
	mc := &MorphedConn{Conn: closeErrConn{cli}, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	if _, err := mc.Write(closeTestPayload(16 << 10)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := mc.Close(); !errors.Is(err, errSockClose) || errors.Is(err, ErrShaperCloseIncomplete) {
		t.Fatalf("Close = %v, want only the socket's error", err)
	}
}

// TestMorphedConnWriteAfterClose: once Close has been called, a shaped
// Write must fail, whether or not an earlier Write had started the pacer.
// Without one, Close skipped the drain and the next Write started a pacer
// on the closed conn: it returned (5000, nil) and nothing was sent.
func TestMorphedConnWriteAfterClose(t *testing.T) {
	for _, writeFirst := range []bool{false, true} {
		name := "no write before close"
		if writeFirst {
			name = "write before close"
		}
		t.Run(name, func(t *testing.T) {
			c := &countingConn{}
			mc := &MorphedConn{Conn: c, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
			if writeFirst {
				if _, err := mc.Write(make([]byte, 5000)); err != nil {
					t.Fatalf("first Write: %v", err)
				}
			}
			if err := mc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			before := c.Writes()
			n, err := mc.Write(make([]byte, 5000))
			if !errors.Is(err, net.ErrClosed) || n != 0 {
				t.Fatalf("Write after Close = (%d, %v), want (0, net.ErrClosed)", n, err)
			}
			if !writeFirst && mc.pacer != nil {
				t.Fatal("Write after Close started a pacer")
			}
			if got := c.Writes(); got != before {
				t.Fatalf("%d writes reached the conn after Close", got-before)
			}
		})
	}
}

// TestMorphedConnFirstWriteRacingClose: the first shaped Write and Close
// race. Before, Close read mc.pacer unsynchronised (a data race), often
// found it nil while Write was creating it, and skipped the drain: both
// returned nil, the frames were never written, and the pacer goroutine
// leaked. Now either Write fails, or every frame it queued reaches the
// conn before Close returns; and no pacer outlives Close.
func TestMorphedConnFirstWriteRacingClose(t *testing.T) {
	for range 300 {
		c := &countingConn{}
		mc := &MorphedConn{Conn: c, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
		var wg sync.WaitGroup
		var writeErr error
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			_, writeErr = mc.Write(make([]byte, 5000))
		})
		wg.Go(func() {
			<-start
			if err := mc.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
		close(start)
		wg.Wait()
		// Close has returned, so every frame Write queued is written.
		sent, _, _, _ := mc.Stats()
		c.mu.Lock()
		written := c.bytes
		c.mu.Unlock()
		if writeErr == nil && written != sent {
			t.Fatalf("Write and Close returned nil, %d of %d framed bytes written", written, sent)
		}
		if writeErr != nil && !errors.Is(writeErr, net.ErrClosed) {
			t.Fatalf("Write = %v, want net.ErrClosed", writeErr)
		}
		if p := mc.pacer; p != nil {
			select {
			case <-p.done:
			default:
				t.Fatal("a pacer was left running after Close")
			}
		}
	}
}

// TestPacerCloseRepeatsFirstResult: a second shutdown returns what the
// first did, not nil.
func TestPacerCloseRepeatsFirstResult(t *testing.T) {
	c := &countingConn{}
	c.failNext.Store(true)
	p := newWritePacer(c, &constShaper{delay: 0})
	if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	first := p.close()
	if !errors.Is(first, ErrShaperCloseIncomplete) {
		t.Fatalf("first close = %v, want ErrShaperCloseIncomplete", first)
	}
	if second := p.close(); second != first {
		t.Fatalf("second close = %v, want the first result %v", second, first)
	}
}

// TestPacerCloseWakesParkedProducer: a producer waiting on a full queue
// must leave as soon as close starts, with net.ErrClosed, instead of
// sitting out the 1 s overflow timer while close waits for it.
func TestPacerCloseWakesParkedProducer(t *testing.T) {
	c := &countingConn{}
	gate := make(chan struct{})
	reached := make(chan struct{})
	c.blockWrite = gate
	c.reachedWrite = reached
	p := newWritePacer(c, &constShaper{delay: 0})
	defer func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}()

	frame := []byte{0}
	if err := p.enqueue(pacedFrame{packet: frame, bucket: -1}); err != nil {
		t.Fatalf("prime enqueue: %v", err)
	}
	<-reached
	for len(p.queue) < cap(p.queue) {
		p.queue <- pacedFrame{packet: frame, bucket: -1}
	}
	parked := make(chan error, 1)
	go func() { parked <- p.enqueue(pacedFrame{packet: frame, bucket: -1}) }()
	// Let the producer get past the non-blocking send and park.
	time.Sleep(50 * time.Millisecond)

	go p.close()
	<-p.done
	select {
	case err := <-parked:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("parked enqueue = %v, want net.ErrClosed", err)
		}
	case <-time.After(pacerEnqueueTimeout / 2):
		t.Fatal("the parked producer did not leave when close started")
	}
}

// TestPacerDrainCountsPartlyWrittenBatch: when the close drain's write
// stops partway through a batch, only the part that did not go out is
// lost.
func TestPacerDrainCountsPartlyWrittenBatch(t *testing.T) {
	gate := make(chan struct{})
	reached := make(chan struct{})
	var calls atomic.Int64
	const frameLen, frames, partial = 1200, 9, 1000
	writev := func(bufs *net.Buffers) (int64, error) {
		if calls.Add(1) == 1 {
			// The pacer's own write of the first frame: hold it until
			// close has started, so the rest goes through the drain.
			close(reached)
			<-gate
			n := buffersLen(*bufs)
			*bufs = nil
			return n, nil
		}
		return partial, errFakeWrite
	}
	p := newWritePacerWithWritev(&countingConn{}, &constShaper{delay: 0}, writev)
	if err := p.enqueue(pacedFrame{packet: make([]byte, frameLen), bucket: -1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	<-reached
	for range frames {
		if err := p.enqueue(pacedFrame{packet: make([]byte, frameLen), bucket: -1}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- p.close() }()
	<-p.done
	close(gate)
	err := <-closed
	if got := calls.Load(); got != 2 {
		t.Fatalf("%d writes, want the first frame and one drain batch", got)
	}
	want := fmt.Sprintf(": %d framed bytes", frames*frameLen-partial)
	if !errors.Is(err, ErrShaperCloseIncomplete) || !strings.Contains(err.Error(), want) {
		t.Fatalf("close = %v, want ErrShaperCloseIncomplete reporting %q", err, want)
	}
}

// stallConn passes writes through until stall is set; from then on a write
// blocks until Close, whatever the deadline.
type stallConn struct {
	net.Conn
	stall  atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func (c *stallConn) Write(b []byte) (int, error) {
	if c.stall.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *stallConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestMorphedConnCloseBoundsCloseNotify: the queue is delivered, but the
// close_notify tls.Conn.Close then sends blocks, as it does when the
// peer's window shuts right after the drain. tls.Conn gives it a 5 s
// deadline of its own, and a conn that ignores deadlines none at all.
// Close must still return closeAbortGrace past its own deadline.
func TestMorphedConnCloseBoundsCloseNotify(t *testing.T) {
	setForTest(t, &pacerCloseTimeout, 100*time.Millisecond)
	setForTest(t, &closeAbortGrace, 300*time.Millisecond)
	c, s := tcpPair(t)
	srvCfg, cliCfg := testTLSConfigs(t)
	srv := tls.Server(s, srvCfg)
	var got atomic.Int64
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := srv.Read(buf)
			got.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	sc := &stallConn{Conn: c, closed: make(chan struct{})}
	cli := tls.Client(sc, cliCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	mc := &MorphedConn{Conn: cli, profile: &TrafficProfile{Name: "T"}, shaper: &chunkShaper{}}
	const size = 16 << 10
	if _, err := mc.Write(closeTestPayload(size)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); got.Load() < size; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the peer got %d of %d bytes", got.Load(), size)
		}
	}
	sc.stall.Store(true)

	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- mc.Close() }()
	select {
	case err := <-closed:
		if took := time.Since(start); took > pacerCloseTimeout+closeAbortGrace+2*time.Second {
			t.Errorf("Close took %v", took)
		}
		if errors.Is(err, ErrShaperCloseIncomplete) {
			t.Fatalf("Close = %v, but the whole queue was delivered", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung on the close_notify")
	}
}
