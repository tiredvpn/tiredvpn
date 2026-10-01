package tun

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// recDeadlineConn forwards to a real conn and remembers the last read
// deadline armed on it.
type recDeadlineConn struct {
	net.Conn
	mu   sync.Mutex
	last time.Time
	n    int
}

func (c *recDeadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.last, c.n = t, c.n+1
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *recDeadlineConn) lastDeadline() (time.Time, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.n
}

// TestReadHandshakeResponseClearsDeadline pins that the reader leaves no read
// deadline behind on any path. The relay hands the conn to a bridge and a
// pump that read without deadlines of their own, so a deadline left on it cut
// the tunnel once it passed, regardless of traffic (issue #93, v3 relay drop).
func TestReadHandshakeResponseClearsDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		wire    []byte
		wantErr bool
	}{
		{"v3 bare 9, nothing follows", tunHandshakeVersion, handshakeBase, false},
		{"v3 bare 9 with frame", tunHandshakeVersion, append(append([]byte{}, handshakeBase...), firstFrame...), false},
		{"v3 probe flag", tunHandshakeVersion, append(append([]byte{}, handshakeBase...), tunFlagMTUProbe), false},
		{"v4 flags 0x00", tunHandshakeVersionDualStack, append(append([]byte{}, handshakeBase...), 0x00), false},
		{"refusal", tunHandshakeVersionDualStack, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, false},
		{"truncated prefix", tunHandshakeVersion, handshakeBase[:5], true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &recDeadlineConn{Conn: chunkedConn(t, tc.wire)}
			_, _, _, err := readHandshakeResponse(conn, tc.version, time.Now().Add(time.Second))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			last, n := conn.lastDeadline()
			if n == 0 {
				t.Fatal("reader armed no deadline for the response read")
			}
			if !last.IsZero() {
				t.Fatalf("reader left a read deadline %v out on the conn", time.Until(last).Round(time.Millisecond))
			}
		})
	}
}

// TestReturnedConnOutlivesResponseDeadline reads the first frame from the
// returned conn well after the response deadline, without arming a deadline
// of its own, the way the relay's bridge reads it.
func TestReturnedConnOutlivesResponseDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		resp    []byte
	}{
		{"v3 bare 9", tunHandshakeVersion, handshakeBase},
		{"v4 flags 0x00", tunHandshakeVersionDualStack, append(append([]byte{}, handshakeBase...), 0x00)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			go func() {
				if _, err := srv.Write(tc.resp); err != nil {
					return
				}
				time.Sleep(700 * time.Millisecond) // past the 200 ms response deadline
				_, _ = srv.Write(firstFrame)
			}()
			_, _, next, err := readHandshakeResponse(cli, tc.version, time.Now().Add(200*time.Millisecond))
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			got := make([]byte, len(firstFrame))
			done := make(chan error, 1)
			go func() {
				_, err := readFullNoDeadline(next, got)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("read after the response deadline: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first frame never arrived")
			}
			if !bytes.Equal(got, firstFrame) {
				t.Fatalf("frame = %x, want %x", got, firstFrame)
			}
		})
	}
}

func readFullNoDeadline(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// TestSilentPeerAfterPrefixFails covers a peer that sends part of an answer
// and goes quiet: the read fails on the response deadline instead of hanging.
// For a v0x04 client the flags byte is mandatory, so a bare prefix is such a
// case; a transport's one-byte refusal is the other.
func TestSilentPeerAfterPrefixFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		wire    []byte
	}{
		{"v4, bare prefix", tunHandshakeVersionDualStack, handshakeBase},
		{"one-byte refusal", tunHandshakeVersion, []byte{0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			go func() { _, _ = srv.Write(tc.wire) }()
			done := make(chan error, 1)
			go func() {
				_, _, _, err := readHandshakeResponse(cli, tc.version, time.Now().Add(300*time.Millisecond))
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("silent peer accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("reader hung on a silent peer")
			}
		})
	}
}

// deadlineDeafConn ignores read deadlines, as the ICMP tunnel's Read does.
type deadlineDeafConn struct{ net.Conn }

func (deadlineDeafConn) SetReadDeadline(time.Time) error { return nil }
func (deadlineDeafConn) SetDeadline(time.Time) error     { return nil }

// TestPeekDoesNotDependOnTransportDeadline: a transport that ignores read
// deadlines must not stretch the v0x03 peek until the first packet arrives.
// The grace is a timer in the reader, and the read it leaves running is
// finished through the returned conn.
func TestPeekDoesNotDependOnTransportDeadline(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		if _, err := srv.Write(handshakeBase); err != nil {
			return
		}
		time.Sleep(1500 * time.Millisecond)
		_, _ = srv.Write(firstFrame)
	}()
	start := time.Now()
	_, n, next, err := readHandshakeResponse(deadlineDeafConn{cli}, tunHandshakeVersion, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("readHandshakeResponse: %v", err)
	}
	if elapsed := time.Since(start); elapsed > handshakeFlagsGrace+500*time.Millisecond {
		t.Fatalf("peek took %v on a deadline-deaf transport, want about %v", elapsed, handshakeFlagsGrace)
	}
	if n != 9 {
		t.Fatalf("n = %d, want 9", n)
	}
	got := make([]byte, len(firstFrame))
	done := make(chan error, 1)
	go func() { _, err := readFullNoDeadline(next, got); done <- err }()
	select {
	case err := <-done:
		if err != nil || !bytes.Equal(got, firstFrame) {
			t.Fatalf("frame after peek = %x, %v; want %x", got, err, firstFrame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first frame incomplete after peek: a byte was lost")
	}
}

// captureConn collects what a ConfusionConn writes, to replay it on the wire
// with chosen segmentation.
type captureConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

// TestPeekKeepsConfusionRecordFraming: the first frame's confusion record
// arrives with its 2-byte header first and its body after the flags grace.
// A peek bounded by a transport read deadline timed out inside the record
// read, after the header was consumed, and the record layer lost its framing
// for good. The timer-bounded peek leaves the read running.
func TestPeekKeepsConfusionRecordFraming(t *testing.T) {
	secret := []byte("confusion-peek-test-secret-32by!")
	nonce := make([]byte, strategy.ConfusionNonceLen)
	const variant = 1

	capt := &captureConn{}
	sc, err := strategy.NewConfusionConn(capt, secret, nonce, variant, false)
	if err != nil {
		t.Fatalf("server conn: %v", err)
	}
	if _, err := sc.Write(handshakeBase); err != nil {
		t.Fatal(err)
	}
	rec1 := append([]byte{}, capt.buf.Bytes()...)
	capt.buf.Reset()
	if _, err := sc.Write(firstFrame); err != nil {
		t.Fatal(err)
	}
	rec2 := append([]byte{}, capt.buf.Bytes()...)

	rawCli, rawSrv := net.Pipe()
	t.Cleanup(func() { rawCli.Close(); rawSrv.Close() })
	go func() {
		if _, err := rawSrv.Write(rec1); err != nil {
			return
		}
		if _, err := rawSrv.Write(rec2[:2]); err != nil { // header now,
			return
		}
		time.Sleep(handshakeFlagsGrace + 300*time.Millisecond) // body after the grace
		_, _ = rawSrv.Write(rec2[2:])
	}()

	cc, err := strategy.NewConfusionConn(rawCli, secret, nonce, variant, true)
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	_, n, next, err := readHandshakeResponse(cc, tunHandshakeVersion, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("readHandshakeResponse: %v", err)
	}
	if n != 9 {
		t.Fatalf("n = %d, want 9", n)
	}
	readFrameAfterHandshake(t, next)
}
