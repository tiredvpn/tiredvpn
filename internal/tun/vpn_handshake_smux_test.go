package tun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// The tests in this file run the TUN handshake over a smux stream, the conn a
// REALITY tunnel hands the client. smux v2 reads a stream's read deadline
// when a Read starts and never again: a deadline set or cleared while a Read
// is blocked does not reach it. The handshake reader's one-byte peek is such
// a Read - started under the response deadline, handed over to the packet
// loop after handshakeFlagsGrace, and still running when the reader clears
// the deadline. On a tunnel that carried nothing down for the rest of the
// response budget it came back with smux's "timeout", and the client dropped
// a healthy session 10 s after connecting (stand twocli/f14-registry,
// "server read: timeout ... session=9.396s").

// smuxPipe returns both ends of one smux stream over an in-memory pipe.
func smuxPipe(t *testing.T) (cli, srv net.Conn) {
	t.Helper()
	cliRaw, srvRaw := net.Pipe()
	cfg := smux.DefaultConfig()
	ss, err := smux.Server(srvRaw, cfg)
	if err != nil {
		t.Fatalf("smux.Server: %v", err)
	}
	cs, err := smux.Client(cliRaw, cfg)
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		s, err := ss.AcceptStream()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- s
	}()
	stream, err := cs.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// smux announces a stream with its first frame: the SYN goes out on
	// OpenStream, so the server end is there before anything is written.
	select {
	case s, ok := <-accepted:
		if !ok {
			t.Fatal("AcceptStream failed")
		}
		return stream, s
	case <-time.After(2 * time.Second):
		t.Fatal("smux stream never accepted")
	}
	return nil, nil
}

// smuxHandshakeTimeout is the response budget of these tests: longer than
// handshakeFlagsGrace, so the peek is handed over before its deadline comes.
const smuxHandshakeTimeout = 600 * time.Millisecond

// TestConnectOverSmuxOutlivesResponseDeadline covers connect(): the exit
// answers a v0x03 client with the bare 9-byte form and sends its first frame
// after the response budget has run out. The packet loop must get the frame.
func TestConnectOverSmuxOutlivesResponseDeadline(t *testing.T) {
	shortHandshakeTimeout(t, smuxHandshakeTimeout)
	m, ps := newPipeManagerWith(t, bareV3Response(), 2*smuxHandshakeTimeout)
	ps.overSmux = true
	v := newCallsiteClient(m)
	if err := v.connect(t.Context()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	readFrameAfterHandshake(t, v.conn)
}

// TestSmuxPeekAfterResponseDeadline drives readHandshakeResponse directly,
// with the follow-up read the way the relay's bridge makes it (no deadline)
// and the way the packet loop makes it (a deadline of its own), and checks
// what the handed-over read must still do.
func TestSmuxPeekAfterResponseDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		// after is what the exit sends once the response budget is over;
		// nil sends nothing.
		after []byte
		// closeAfter closes the exit end instead.
		closeAfter bool
		// readDeadline is the deadline the reader sets before its read,
		// zero for none.
		readDeadline time.Duration
		wantFrame    bool
		wantErr      error // nil: any error
	}{
		{name: "frame, no deadline", after: firstFrame, wantFrame: true},
		{name: "frame, own deadline", after: firstFrame, readDeadline: 3 * time.Second, wantFrame: true},
		{name: "late flags byte still fails", after: []byte{0x01}, readDeadline: 3 * time.Second, wantErr: errLateHandshakeFlags},
		{name: "own deadline still bounds the read", readDeadline: 2 * smuxHandshakeTimeout},
		{name: "close still ends it", closeAfter: true, readDeadline: 3 * time.Second, wantErr: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := smuxPipe(t)
			start := time.Now()
			go func() {
				if _, err := srv.Write(handshakeBase); err != nil {
					return
				}
				time.Sleep(2 * smuxHandshakeTimeout)
				switch {
				case tc.closeAfter:
					srv.Close()
				case tc.after != nil:
					_, _ = srv.Write(tc.after)
				}
			}()
			_, _, next, err := readHandshakeResponse(cli, tunHandshakeVersion, start.Add(smuxHandshakeTimeout))
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if _, ok := next.(*replayConn); !ok {
				t.Fatalf("returned conn is %T: the peek was not handed over, the test does not reach the case", next)
			}
			if tc.readDeadline > 0 {
				if err := next.SetReadDeadline(time.Now().Add(tc.readDeadline)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
			}
			got := make([]byte, len(firstFrame))
			done := make(chan error, 1)
			go func() {
				_, err := io.ReadFull(next, got)
				done <- err
			}()
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("read never returned")
			}
			if tc.wantFrame {
				if err != nil {
					t.Fatalf("read after the response deadline (%v in): %v", time.Since(start).Round(time.Millisecond), err)
				}
				if !bytes.Equal(got, firstFrame) {
					t.Fatalf("frame = %x, want %x", got, firstFrame)
				}
				return
			}
			if err == nil {
				t.Fatal("read succeeded, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("read error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil {
				// The deadline the reader set, not the response's, ends it.
				if el := time.Since(start); el < 2*smuxHandshakeTimeout {
					t.Fatalf("read ended %v in, before the reader's own deadline", el.Round(time.Millisecond))
				}
			}
		})
	}
}
