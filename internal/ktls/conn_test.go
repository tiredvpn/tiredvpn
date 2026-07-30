package ktls

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

// The relay fast path in optimizedRelay only reaches splice(2) when *Conn
// satisfies these; losing either one silently degrades every kTLS relay to a
// userspace copy loop.
var (
	_ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo   = (*Conn)(nil)
)

// tcpPair returns a connected pair of loopback TCP connections.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-accepted
	if res.err != nil {
		c.Close()
		t.Fatalf("accept: %v", res.err)
	}

	client = c.(*net.TCPConn)
	server = res.conn.(*net.TCPConn)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// TestCopyBetweenConns relays several hundred KB through io.Copy with a *Conn on
// both ends, which is the shape optimizedRelay produces once kTLS is enabled.
// kTLS itself is not engaged here: post-enable the wrapper delegates to the raw
// TCP socket, so plain loopback sockets exercise the same code path.
func TestCopyBetweenConns(t *testing.T) {
	srcWriter, srcReader := tcpPair(t)
	dstWriter, dstReader := tcpPair(t)

	src := &Conn{tcpConn: srcReader}
	dst := &Conn{tcpConn: dstWriter}

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	go func() {
		srcWriter.Write(payload)
		srcWriter.CloseWrite()
	}()

	copied := make(chan int64, 1)
	copyErr := make(chan error, 1)
	go func() {
		n, err := io.Copy(dst, src)
		copied <- n
		copyErr <- err
		dstWriter.CloseWrite()
	}()

	got, err := io.ReadAll(dstReader)
	if err != nil {
		t.Fatalf("read relayed data: %v", err)
	}
	if err := <-copyErr; err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if n := <-copied; n != int64(len(payload)) {
		t.Fatalf("io.Copy reported %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed data differs: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestReadFrom_NonConnSource covers the branch where the source is not a *Conn
// (e.g. replaying a buffered prefix), so no unwrap happens.
func TestReadFrom_NonConnSource(t *testing.T) {
	writer, reader := tcpPair(t)
	dst := &Conn{tcpConn: writer}

	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := dst.ReadFrom(bytes.NewReader(payload))
		writer.CloseWrite()
		errCh <- err
	}()

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("data differs: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestWriteTo_PlainWriter covers the io.Copy fallback in WriteTo for
// destinations that implement neither *Conn nor io.ReaderFrom.
func TestWriteTo_PlainWriter(t *testing.T) {
	writer, reader := tcpPair(t)
	src := &Conn{tcpConn: reader}

	payload := []byte("plain writer destination, no ReaderFrom fast path")
	go func() {
		writer.Write(payload)
		writer.CloseWrite()
	}()

	var sink plainWriter
	n, err := src.WriteTo(&sink)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("WriteTo reported %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(sink.buf, payload) {
		t.Fatalf("data differs: got %q, want %q", sink.buf, payload)
	}
}

// plainWriter deliberately implements only io.Writer so io.Copy inside WriteTo
// cannot promote it to a ReaderFrom fast path.
type plainWriter struct {
	buf []byte
}

func (w *plainWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func TestTryEnable_NotTLSReturnsOriginal(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	got := TryEnable(a, "test-label")
	if got != a {
		t.Fatalf("TryEnable on non-TLS conn must return the original; got %T", got)
	}
}

func TestTryEnable_AlreadyKTLSReturnsSame(t *testing.T) {
	// Construct a *Conn directly (no real socket) to exercise the early-return path.
	k := &Conn{}
	got := TryEnable(k, "test-label")
	if got != k {
		t.Fatalf("TryEnable on *ktls.Conn must return the same value; got %T", got)
	}
}
