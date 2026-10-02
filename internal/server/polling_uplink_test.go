package server

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// The meek uplink is a byte stream that the HTTP handler appends to, one
// request body at a time, while the session's relay goroutine drains it. The
// client cuts that stream into bodies with no regard for TUN framing (8 KiB
// chunks), so the relay routinely holds the head of a frame whose tail is still
// in flight. These tests push such a stream through the real relay loops while
// bodies keep arriving, the way a busy client does, and check what comes out
// the other side byte for byte.

// newPollingSession builds a session the way GetOrCreate does, without putting
// it in the global manager.
func newPollingSession(id string) *HTTPPollingSession {
	return &HTTPPollingSession{
		ID:         id,
		Created:    time.Now(),
		LastActive: time.Now(),
		toClient:   bytes.NewBuffer(nil),
		fromClient: bytes.NewBuffer(nil),
	}
}

// uplinkPacket builds a minimal IPv4 packet whose payload carries seq and a
// pattern derived from it, so reordering, loss and corruption are all visible.
func uplinkPacket(seq uint32, size int) []byte {
	if size < 28 {
		size = 28
	}
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[9] = 17
	copy(p[12:16], net.IPv4(10, 99, 0, 9).To4())
	copy(p[16:20], net.IPv4(10, 99, 0, 1).To4())
	binary.BigEndian.PutUint32(p[20:24], seq)
	for i := 24; i < size; i++ {
		p[i] = byte(seq) ^ byte(i)
	}
	return p
}

// feedInBodies appends stream to the session the way processHTTPPollingRequest
// does, in bodies of random size up to the client's 8 KiB upload chunk. Bodies
// arrive back to back, as they do from a client with a full send buffer.
func feedInBodies(sess *HTTPPollingSession, stream []byte, rng *rand.Rand, stop <-chan struct{}) {
	for len(stream) > 0 {
		select {
		case <-stop:
			return
		default:
		}
		n := 1 + rng.Intn(8192)
		if n > len(stream) {
			n = len(stream)
		}
		body := make([]byte, n) // the handler allocates a fresh body per request
		copy(body, stream[:n])
		stream = stream[n:]
		for !sess.WriteFromClient(body) {
			// Backpressure: the handler refused the body, the client re-sends it.
			time.Sleep(time.Millisecond)
		}
		if rng.Intn(4) == 0 {
			time.Sleep(time.Duration(rng.Intn(300)) * time.Microsecond)
		}
	}
}

// TestPollingTUNUplinkSurvivesBodiesArrivingMidParse drives runPollingTUNMode
// itself - the loop that used to drain the buffer, parse, and append its
// unparsed tail back behind whatever body arrived meanwhile - and checks that
// every IP packet reaches the TUN device intact and in order.
func TestPollingTUNUplinkSurvivesBodiesArrivingMidParse(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// The relay writes each packet to the "TUN device"; a SEQPACKET socket keeps
	// packet boundaries, so the far end reads exactly what the kernel would.
	dev, err := tun.CreateTUNFromFd(fds[0], "fxpoll0", 1500)
	if err != nil {
		t.Fatalf("tun from fd: %v", err)
	}
	tunEnd := os.NewFile(uintptr(fds[1]), "tun-far-end")
	defer tunEnd.Close()

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.TunIP = net.IPv4(10, 99, 0, 1).To4()
	srvCtx.sharedTUN = &SharedTUN{
		name:          "fxpoll0",
		tunDev:        dev,
		clients:       make(map[string]*ClientWriter),
		reconnTracker: newReconnectTracker(10),
		stopCh:        make(chan struct{}),
	}
	sess := newPollingSession("fxpolltunsession")
	defer sess.Close()

	// TUN handshake as the client sends it: [localIP:4][mtu:2][version:1].
	hs := []byte{10, 99, 0, 9, 0x05, 0x00, 0x03}
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		runPollingTUNMode(sess, hs, srvCtx, testLogger(t))
	}()

	const packets = 3000
	rng := rand.New(rand.NewSource(1))
	var stream []byte
	want := make([][]byte, packets)
	for i := range want {
		want[i] = uplinkPacket(uint32(i), 28+rng.Intn(1372))
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(want[i])))
		stream = append(stream, hdr[:]...)
		stream = append(stream, want[i]...)
		if rng.Intn(10) == 0 {
			stream = append(stream, 0, 0, 0, 0) // a keepalive now and then
		}
	}

	stop := make(chan struct{})
	defer close(stop)
	go feedInBodies(sess, stream, rand.New(rand.NewSource(2)), stop)

	buf := make([]byte, 2048)
	for i := 0; i < packets; i++ {
		tunEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := tunEnd.Read(buf)
		if err != nil {
			select {
			case <-relayDone:
				t.Fatalf("relay loop exited after %d of %d packets (session torn down on a garbage length)", i, packets)
			default:
			}
			t.Fatalf("packet %d: read from TUN: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want[i]) {
			got := uint32(0)
			if n >= 24 {
				got = binary.BigEndian.Uint32(buf[20:24])
			}
			t.Fatalf("packet %d: got %d bytes with seq %d, want %d bytes with seq %d - the uplink was reordered or overwritten",
				i, n, got, len(want[i]), i)
		}
	}
}

// TestPollingSOCKSUplinkArrivesIntact covers the non-TUN mode: the same buffer
// carries a raw byte stream to a proxied target. The relay used to hand the
// target a slice that still aliased the session buffer, which the next body
// overwrote while the write to the target was in progress.
func TestPollingSOCKSUplinkArrivesIntact(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const size = 4 << 20
	payload := make([]byte, size)
	rand.New(rand.NewSource(3)).Read(payload)
	wantSum := sha256.Sum256(payload)

	gotSum := make(chan [32]byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetReadBuffer(64 << 10) // a slow target keeps the relay's writes blocked
		}
		h := sha256.New()
		buf := make([]byte, 4096)
		var got int
		for got < size {
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := c.Read(buf)
			h.Write(buf[:n])
			got += n
			if err != nil {
				break
			}
			if got < 512<<10 {
				time.Sleep(200 * time.Microsecond)
			}
		}
		var s [32]byte
		copy(s[:], h.Sum(nil))
		gotSum <- s
	}()

	srvCtx := newTestServerContext(t)
	sess := newPollingSession("fxpollsockssessn")
	defer sess.Close()

	addr := ln.Addr().String()
	head := make([]byte, 2+len(addr))
	binary.BigEndian.PutUint16(head[:2], uint16(len(addr)))
	copy(head[2:], addr)
	stream := append(head, payload...)

	go runPollingSessionRelay(sess, srvCtx, testLogger(t))
	stop := make(chan struct{})
	defer close(stop)
	go feedInBodies(sess, stream, rand.New(rand.NewSource(4)), stop)

	select {
	case s := <-gotSum:
		if s != wantSum {
			t.Fatalf("target received a different stream: sha256 %x, want %x", s, wantSum)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("target did not receive the whole stream in 60s")
	}
}

// pollOnce sends one poll request with body through processHTTPPollingRequest
// the way the meek client does (token bound to ekm, see verifyPollingAuth) and
// returns the HTTP status the client would see.
func pollOnce(t *testing.T, sessionID string, secret, ekm, body []byte) int {
	t.Helper()
	return pollOnceSlow(t, sessionID, secret, ekm, body, 0)
}

// slowBody delivers its body only after delay, the way a body held up by
// retransmissions on a lossy path reaches the server well after its headers.
type slowBody struct {
	delay time.Duration
	r     io.Reader
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.delay > 0 {
		time.Sleep(b.delay)
		b.delay = 0
	}
	return b.r.Read(p)
}

func pollOnceSlow(t *testing.T, sessionID string, secret, ekm, body []byte, delay time.Duration) int {
	t.Helper()
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s:%d", sessionID, time.Now().Unix())
	h.Write(ekm)
	token := base64.StdEncoding.EncodeToString(h.Sum(nil))[:16]
	request := []byte(fmt.Sprintf("POST /poll HTTP/1.1\r\nX-Session-ID: %s\r\nX-Auth-Token: %s\r\n"+
		"X-Ack: 0\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", sessionID, token, len(body)))

	srvEnd, cliEnd := net.Pipe()
	defer srvEnd.Close()
	defer cliEnd.Close()
	status := make(chan int, 1)
	go func() {
		cliEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(cliEnd), nil)
		if err != nil {
			status <- -1
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	processHTTPPollingRequest(srvEnd, bufio.NewReader(&slowBody{delay: delay, r: bytes.NewReader(body)}), newTestServerContext(t), request, ekm, testLogger(t))
	return <-status
}

// TestPollingUplinkRefusedBodyIsNotLost covers the uplink bound. A body that
// does not fit must be refused whole with a non-200, so the client keeps it and
// sends it again (internal/strategy/http_polling.go poll() puts the bytes of a
// failed request back at the front of its send buffer), and must not land in the
// session at all - neither silently dropped behind a 200 nor partly written.
func TestPollingUplinkRefusedBodyIsNotLost(t *testing.T) {
	secret := []byte("fx-polling-uplink-secret")
	ekm := bytes.Repeat([]byte{0x5a}, 32)
	sess := newPollingSession("fxpollfullsessn0")
	sess.Secret = secret
	pollingManager.mu.Lock()
	pollingManager.sessions[sess.ID] = sess
	pollingManager.mu.Unlock()
	defer pollingManager.Remove(sess.ID)

	rng := rand.New(rand.NewSource(5))
	backlog := make([]byte, maxFromClientBuffered-1000)
	rng.Read(backlog)
	if !sess.WriteFromClient(backlog) {
		t.Fatal("a backlog under the bound was refused")
	}
	body := make([]byte, 8192) // the client's upload chunk
	rng.Read(body)

	if st := pollOnce(t, sess.ID, secret, ekm, body); st == http.StatusOK {
		t.Fatalf("a body over the uplink bound was answered %d: the client drops bytes it was told were taken", st)
	}
	if got := sess.ReadFromClient(); !bytes.Equal(got, backlog) {
		t.Fatalf("the refused body changed the uplink: have %d bytes, want the %d-byte backlog untouched", len(got), len(backlog))
	}

	// The relay has drained; the client's re-send now goes through, once.
	if st := pollOnce(t, sess.ID, secret, ekm, body); st != http.StatusOK {
		t.Fatalf("the re-sent body was answered %d with room in the uplink", st)
	}
	if got := sess.ReadFromClient(); !bytes.Equal(got, body) {
		t.Fatalf("after the re-send the uplink holds %d bytes, want exactly the %d-byte body", len(got), len(body))
	}
}

// TestPollingSOCKSPreludeKeepsPayloadOrder targets the moment the relay parses
// the target address: whatever follows the address in the same read is the
// start of the payload and must reach the target before anything that arrives
// later. The prelude used to write it back into the session, behind any body
// that came in meanwhile. Bodies here are tiny and back to back, so one is
// almost always arriving while the prelude runs.
func TestPollingSOCKSPreludeKeepsPayloadOrder(t *testing.T) {
	for round := 0; round < 20; round++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		payload := make([]byte, 64<<10)
		rand.New(rand.NewSource(int64(6 + round))).Read(payload)
		got := make(chan []byte, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- nil
				return
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			b := make([]byte, len(payload))
			n, _ := io.ReadFull(c, b)
			got <- b[:n]
		}()

		sess := newPollingSession(fmt.Sprintf("fxpollprelude%03d", round))
		addr := ln.Addr().String()
		first := make([]byte, 2+len(addr)+16) // address plus the first payload bytes
		binary.BigEndian.PutUint16(first[:2], uint16(len(addr)))
		copy(first[2:], addr)
		copy(first[2+len(addr):], payload[:16])
		sess.WriteFromClient(first)
		go runPollingSessionRelay(sess, newTestServerContext(t), testLogger(t))
		go func(rest []byte) {
			for i := 0; len(rest) > 0; i++ {
				n := 1 + i%32
				if n > len(rest) {
					n = len(rest)
				}
				body := append([]byte(nil), rest[:n]...)
				for !sess.WriteFromClient(body) {
					runtime.Gosched()
				}
				rest = rest[n:]
				runtime.Gosched()
			}
		}(payload[16:])

		b := <-got
		sess.Close()
		ln.Close()
		if !bytes.Equal(b, payload) {
			i := 0
			for i < len(b) && b[i] == payload[i] {
				i++
			}
			t.Fatalf("round %d: target stream diverges at byte %d of %d - the payload after the address was reordered", round, i, len(payload))
		}
	}
}

// TestPollingUplinkRefusesLateBody covers the abandoned request. The client
// gives a request 3s and then re-sends its body on a new connection; a copy that
// completes on the server after that is a duplicate in a stream with no sequence
// numbers. A body that took longer than pollingUplinkCommitBudget after its
// headers is refused and leaves the uplink untouched; the same body on time
// goes through once.
func TestPollingUplinkRefusesLateBody(t *testing.T) {
	secret := []byte("fx-polling-uplink-secret")
	ekm := bytes.Repeat([]byte{0x3c}, 32)
	sess := newPollingSession("fxpolllatesessn0")
	sess.Secret = secret
	pollingManager.mu.Lock()
	pollingManager.sessions[sess.ID] = sess
	pollingManager.mu.Unlock()
	defer pollingManager.Remove(sess.ID)

	body := make([]byte, 8192)
	rand.New(rand.NewSource(7)).Read(body)

	if st := pollOnceSlow(t, sess.ID, secret, ekm, body, pollingUplinkCommitBudget+200*time.Millisecond); st == http.StatusOK {
		t.Fatalf("a body that arrived %v after its headers was answered %d", pollingUplinkCommitBudget+200*time.Millisecond, st)
	}
	if got := sess.ReadFromClient(); len(got) != 0 {
		t.Fatalf("the late body was written into the uplink (%d bytes): the client re-sends it, so the stream now holds it twice", len(got))
	}
	if st := pollOnce(t, sess.ID, secret, ekm, body); st != http.StatusOK {
		t.Fatalf("the re-sent body was answered %d", st)
	}
	if got := sess.ReadFromClient(); !bytes.Equal(got, body) {
		t.Fatalf("after the re-send the uplink holds %d bytes, want exactly the %d-byte body", len(got), len(body))
	}
}
