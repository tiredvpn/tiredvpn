//go:build linux

package ktls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// These tests hand a live TLS 1.3 client connection to the kernel at the
// moments where crypto/tls still holds input the kernel cannot see, and check
// the byte stream survives in both directions. The server issues a session
// ticket, as crypto/tls does whenever the client has a session cache, so every
// case starts with a NewSessionTicket right behind the server's Finished.

// requireKernelTLS skips unless this kernel accepts the tls ULP on a live TCP
// socket, which is what Enable needs; CI runners often lack the module.
func requireKernelTLS(t *testing.T) {
	t.Helper()
	if !Supported() {
		t.Skip("kernel TLS not available")
	}
	c, _ := tcpPair(t)
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ulpErr error
	if err := raw.Control(func(fd uintptr) {
		ulpErr = syscall.SetsockoptString(int(fd), syscall.SOL_TCP, 31 /* TCP_ULP */, "tls")
	}); err != nil {
		t.Fatal(err)
	}
	if ulpErr != nil {
		t.Skipf("tls ULP unavailable: %v", ulpErr)
	}
}

// oneByteReads hands crypto/tls at most one byte per Read, so it never reads
// past what it needs and the session ticket stays on the socket.
type oneByteReads struct{ net.Conn }

func (o oneByteReads) Read(b []byte) (int, error) { return o.Conn.Read(b[:1]) }

// stallingWriter passes the first stallAfter bytes of the Nth Write through,
// then sleeps before the rest: a peer that stops in the middle of a record.
type stallingWriter struct {
	net.Conn
	nth, calls int
	stallAfter int
	stall      time.Duration
}

func (s *stallingWriter) Write(b []byte) (int, error) {
	s.calls++
	if s.calls != s.nth || len(b) <= s.stallAfter {
		return s.Conn.Write(b)
	}
	n, err := s.Conn.Write(b[:s.stallAfter])
	if err != nil {
		return n, err
	}
	time.Sleep(s.stall)
	m, err := s.Conn.Write(b[s.stallAfter:])
	return n + m, err
}

type handoverServer struct {
	addr    string
	payload []byte      // written right after the handshake
	echoed  chan []byte // what the server read back from the client
	wrap    func(net.Conn) net.Conn
	chunks  int // payload is written in this many Writes (records)

	// gate, if set, holds every record after the first until it is closed,
	// so the client can act while only the first record has arrived.
	gate chan struct{}
	// closeRaw ends the stream by closing TCP right after the payload,
	// without close_notify and without reading anything back.
	closeRaw bool
	// closeNotify sends close_notify right after the payload but keeps the
	// TCP connection open: no FIN follows.
	closeNotify bool
}

func startHandoverServer(t *testing.T, payload []byte, echoLen, chunks int, wrap func(net.Conn) net.Conn) *handoverServer {
	t.Helper()
	return startHandoverServerOpts(t, &handoverServer{payload: payload, chunks: chunks, wrap: wrap}, echoLen)
}

func startHandoverServerOpts(t *testing.T, hs *handoverServer, echoLen int) *handoverServer {
	t.Helper()
	payload := hs.payload
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	hs.addr = ln.Addr().String()
	hs.echoed = make(chan []byte, 1)
	cert := selfSigned(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if hs.wrap != nil {
			c = hs.wrap(c)
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		if err := s.Handshake(); err != nil {
			return
		}
		step := (len(payload) + hs.chunks - 1) / hs.chunks
		for off := 0; off < len(payload); off += step {
			if off > 0 && hs.gate != nil {
				<-hs.gate
			}
			if _, err := s.Write(payload[off:min(off+step, len(payload))]); err != nil {
				return
			}
		}
		if hs.closeRaw {
			return // deferred c.Close: FIN, no close_notify
		}
		if hs.closeNotify {
			s.CloseWrite()
			io.Copy(io.Discard, c) // hold TCP open until the client goes
			return
		}
		got := make([]byte, echoLen)
		s.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ := io.ReadFull(s, got)
		hs.echoed <- got[:n]
		// Hold the conn open until the client is done reading.
		io.Copy(io.Discard, s)
	}()
	return hs
}

func dialHandoverClient(t *testing.T, addr string, wrap func(net.Conn) net.Conn) *tls.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	under := c
	if wrap != nil {
		under = wrap(c)
	}
	tc := tls.Client(under, &tls.Config{
		InsecureSkipVerify: true, // self-signed test server
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(4), // makes the server send a ticket
	})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// checkStream reads want from r and writes echo through w to the server.
//
// It deliberately sets no read deadline: whatever deadline Enable leaves on
// the socket is what the reads run under, so a settle that forgot to clear
// its own shows up here. A watchdog closes the conn if the read hangs.
func checkStream(t *testing.T, r io.Reader, w io.Writer, hs *handoverServer, want, echo []byte) {
	t.Helper()
	if c, ok := r.(io.Closer); ok {
		stop := time.AfterFunc(10*time.Second, func() { c.Close() })
		defer stop.Stop()
	}
	got := make([]byte, len(want))
	if n, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read after handover: %d/%d bytes: %v", n, len(want), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream after handover differs from what the server sent")
	}
	if _, err := w.Write(echo); err != nil {
		t.Fatalf("write after handover: %v", err)
	}
	select {
	case e := <-hs.echoed:
		if !bytes.Equal(e, echo) {
			t.Fatalf("server read %d bytes back, not the %d the client wrote", len(e), len(echo))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server never read the client's bytes")
	}
}

// TestHandoverTicketBufferedByCryptoTLS is the http2_stego client shape:
// kTLS right after the handshake, before anything was read. crypto/tls has
// by then read the head of the server's NewSessionTicket record off the
// socket, so the kernel, left on its own, starts decrypting mid-record.
func TestHandoverTicketBufferedByCryptoTLS(t *testing.T) {
	requireKernelTLS(t)
	payload := randBytes(t, 256<<10)
	echo := randBytes(t, 64<<10)
	hs := startHandoverServer(t, payload, len(echo), 16, nil)
	tc := dialHandoverClient(t, hs.addr, nil)

	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if bufs.empty() {
		t.Fatal("precondition: crypto/tls buffered nothing past Finished, the case under test did not happen")
	}

	k := Enable(tc)
	if k == nil {
		t.Fatal("Enable fell back to userspace TLS")
	}
	checkStream(t, k, k, hs, payload, echo)
}

// TestHandoverTicketStillOnSocket: nothing is buffered, the ticket arrives
// at the kernel, which hands it up as a non-data record.
func TestHandoverTicketStillOnSocket(t *testing.T) {
	requireKernelTLS(t)
	payload := randBytes(t, 256<<10)
	echo := randBytes(t, 64<<10)
	hs := startHandoverServer(t, payload, len(echo), 16, nil)
	tc := dialHandoverClient(t, hs.addr, func(c net.Conn) net.Conn { return oneByteReads{c} })

	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if !bufs.empty() {
		t.Fatal("precondition: crypto/tls buffered input, the ticket is not on the socket")
	}

	k := Enable(tc)
	if k == nil {
		t.Fatal("Enable fell back to userspace TLS")
	}
	checkStream(t, k, k, hs, payload, echo)
}

// TestHandoverAfterPartialRead: the caller read part of a record through
// crypto/tls; the decrypted rest sits in crypto/tls and must come out of the
// kTLS conn first, followed by the records still on the socket.
func TestHandoverAfterPartialRead(t *testing.T) {
	requireKernelTLS(t)
	payload := randBytes(t, 256<<10)
	echo := randBytes(t, 64<<10)
	hs := startHandoverServer(t, payload, len(echo), 16, nil)
	tc := dialHandoverClient(t, hs.addr, nil)

	first := make([]byte, 100)
	if _, err := io.ReadFull(tc, first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, payload[:100]) {
		t.Fatal("userspace read before handover differs")
	}
	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if bufs.input.Len() == 0 {
		t.Fatal("precondition: no decrypted data left in crypto/tls")
	}

	k := Enable(tc)
	if k == nil {
		t.Fatal("Enable fell back to userspace TLS")
	}
	checkStream(t, k, k, hs, payload[100:], echo)
}

// TestHandoverFallbackKeepsDrainedData: the server stops in the middle of a
// record for longer than Enable waits. Enable must give up, and the data it
// already decrypted while settling must still come out of the *tls.Conn.
func TestHandoverFallbackKeepsDrainedData(t *testing.T) {
	requireKernelTLS(t)
	old := settleReadTimeout
	settleReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { settleReadTimeout = old })

	payload := randBytes(t, 4<<10)
	echo := randBytes(t, 1<<10)
	// Server Writes on the raw conn: 1 = its handshake flight (with the
	// ticket), then one per payload record. Stall 10 bytes into record 2.
	hs := startHandoverServer(t, payload, len(echo), 2, func(c net.Conn) net.Conn {
		return &stallingWriter{Conn: c, nth: 3, stallAfter: 10, stall: 1500 * time.Millisecond}
	})
	tc := dialHandoverClient(t, hs.addr, nil)

	// Let record 1 and the head of record 2 arrive, then read one byte so
	// crypto/tls decrypts record 1 and pulls the head of record 2 along.
	time.Sleep(300 * time.Millisecond)
	first := make([]byte, 1)
	if _, err := io.ReadFull(tc, first); err != nil {
		t.Fatal(err)
	}
	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if bufs.input.Len() == 0 || bufs.rawInput.Len() == 0 {
		t.Fatalf("precondition: want decrypted data and a split record buffered, have input=%d raw=%d",
			bufs.input.Len(), bufs.rawInput.Len())
	}

	_, fbBefore := Stats()
	if k := Enable(tc); k != nil {
		t.Fatal("Enable took over a conn whose record tail never arrived")
	}
	if _, fb := Stats(); fb <= fbBefore {
		t.Fatal("fallback not counted")
	}
	checkStream(t, tc, tc, hs, payload[1:], echo)
}

// partialReadHandover returns a kTLS conn over a session where the caller has
// read 100 bytes of a 1000-byte first record through crypto/tls: the other
// 900 are decrypted and waiting in crypto/tls, and rawInput is empty because
// the next record is held back by the server until gate is closed.
func partialReadHandover(t *testing.T, hs *handoverServer) (*Conn, *tls.Conn) {
	t.Helper()
	tc := dialHandoverClient(t, hs.addr, nil)
	first := make([]byte, 100)
	if _, err := io.ReadFull(tc, first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, hs.payload[:100]) {
		t.Fatal("userspace read before handover differs")
	}
	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if bufs.input.Len() != 900 || bufs.rawInput.Len() != 0 || bufs.hand.Len() != 0 {
		t.Fatalf("precondition: want only 900 decrypted bytes buffered, have input=%d raw=%d hand=%d",
			bufs.input.Len(), bufs.rawInput.Len(), bufs.hand.Len())
	}
	k := Enable(tc)
	if k == nil {
		t.Fatal("Enable fell back to userspace TLS")
	}
	return k, tc
}

// TestHandoverDecryptedDataOnly: nothing raw is buffered, only plaintext
// crypto/tls already decrypted. Settling must still run for it.
func TestHandoverDecryptedDataOnly(t *testing.T) {
	requireKernelTLS(t)
	echo := randBytes(t, 4<<10)
	hs := startHandoverServerOpts(t, &handoverServer{payload: randBytes(t, 3000), chunks: 3, gate: make(chan struct{})}, len(echo))
	k, _ := partialReadHandover(t, hs)
	close(hs.gate)
	checkStream(t, k, k, hs, hs.payload[100:], echo)
}

// TestHandoverWriteToFlushesPending: the relay copies out of a kTLS conn with
// io.Copy, which goes through WriteTo; the handover leftovers must lead.
func TestHandoverWriteToFlushesPending(t *testing.T) {
	requireKernelTLS(t)
	hs := startHandoverServerOpts(t, &handoverServer{payload: randBytes(t, 3000), chunks: 3, gate: make(chan struct{}), closeRaw: true}, 0)
	k, _ := partialReadHandover(t, hs)
	close(hs.gate)

	var got bytes.Buffer
	stop := time.AfterFunc(10*time.Second, func() { k.Close() })
	defer stop.Stop()
	if _, err := k.WriteTo(&got); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if !bytes.Equal(got.Bytes(), hs.payload[100:]) {
		t.Fatalf("WriteTo delivered %d bytes, want the %d after the userspace read", got.Len(), len(hs.payload)-100)
	}
}

// TestHandoverReadFromFlushesPending: the same copy seen from the
// destination side, a *Conn whose ReadFrom is handed the kTLS source.
func TestHandoverReadFromFlushesPending(t *testing.T) {
	requireKernelTLS(t)
	hs := startHandoverServerOpts(t, &handoverServer{payload: randBytes(t, 3000), chunks: 3, gate: make(chan struct{}), closeRaw: true}, 0)
	src, _ := partialReadHandover(t, hs)
	close(hs.gate)

	a, b := tcpPair(t)
	dst := &Conn{tcpConn: a}
	done := make(chan []byte, 1)
	go func() {
		got, _ := io.ReadAll(b)
		done <- got
	}()
	stop := time.AfterFunc(10*time.Second, func() { src.Close(); a.Close() })
	defer stop.Stop()
	if _, err := dst.ReadFrom(src); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	a.CloseWrite()
	if got := <-done; !bytes.Equal(got, hs.payload[100:]) {
		t.Fatalf("ReadFrom delivered %d bytes, want the %d after the userspace read", len(got), len(hs.payload)-100)
	}
}

// TestHandoverCloseNotifyWhileSettling: the peer's close_notify is among the
// records settled in userspace and no FIN follows. After the leftover data
// the kTLS conn must report EOF instead of waiting on the socket.
func TestHandoverCloseNotifyWhileSettling(t *testing.T) {
	requireKernelTLS(t)
	hs := startHandoverServerOpts(t, &handoverServer{payload: randBytes(t, 1000), chunks: 1, closeNotify: true}, 0)
	tc := dialHandoverClient(t, hs.addr, nil)
	time.Sleep(100 * time.Millisecond) // let the record and close_notify arrive together
	first := make([]byte, 100)
	if _, err := io.ReadFull(tc, first); err != nil {
		t.Fatal(err)
	}
	bufs, err := tlsReceiveBuffers(tc)
	if err != nil {
		t.Fatal(err)
	}
	if bufs.input.Len() != 900 || bufs.rawInput.Len() == 0 {
		t.Fatalf("precondition: want 900 decrypted bytes and the alert buffered, have input=%d raw=%d",
			bufs.input.Len(), bufs.rawInput.Len())
	}
	k := Enable(tc)
	if k == nil {
		t.Fatal("Enable fell back to userspace TLS")
	}
	stop := time.AfterFunc(5*time.Second, func() { k.Close() })
	defer stop.Stop()
	got, err := io.ReadAll(k)
	if err != nil {
		t.Fatalf("after close_notify: %v (read %d bytes)", err, len(got))
	}
	if !bytes.Equal(got, hs.payload[100:]) {
		t.Fatalf("read %d bytes, want %d", len(got), len(hs.payload)-100)
	}
}

// TestHandoverConcurrentReads: net.Conn allows concurrent calls; two readers
// draining the handover leftovers must not race (run under -race).
func TestHandoverConcurrentReads(t *testing.T) {
	requireKernelTLS(t)
	hs := startHandoverServerOpts(t, &handoverServer{payload: randBytes(t, 3000), chunks: 3, gate: make(chan struct{}), closeRaw: true}, 0)
	k, _ := partialReadHandover(t, hs)
	close(hs.gate)
	stop := time.AfterFunc(10*time.Second, func() { k.Close() })
	defer stop.Stop()

	counts := make(chan int, 2)
	for range 2 {
		go func() {
			n := 0
			b := make([]byte, 7)
			for {
				m, err := k.Read(b)
				n += m
				if err != nil {
					counts <- n
					return
				}
			}
		}()
	}
	if total := <-counts + <-counts; total != len(hs.payload)-100 {
		t.Fatalf("readers got %d bytes between them, want %d", total, len(hs.payload)-100)
	}
}
