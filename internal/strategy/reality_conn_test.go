package strategy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestRealityDataConnRoundTrip(t *testing.T) {
	t.Parallel()

	secret := []byte("test-shared-secret")
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	clientConn, err := NewRealityDataConn(clientRaw, secret, pubKey, true)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := NewRealityDataConn(serverRaw, secret, pubKey, false)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello from client")
	reply := []byte("ack from server")

	type result struct {
		data []byte
		err  error
	}

	// Server: read msg, then write reply.
	serverDone := make(chan result, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			serverDone <- result{err: err}
			return
		}
		if _, err := serverConn.Write(reply); err != nil {
			serverDone <- result{err: err}
			return
		}
		serverDone <- result{data: buf}
	}()

	// Client: write msg, then read reply.
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatal("client write:", err)
	}

	ack := make([]byte, len(reply))
	if _, err := io.ReadFull(clientConn, ack); err != nil {
		t.Fatal("client read reply:", err)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatal("server error:", res.err)
	}
	if !bytes.Equal(res.data, msg) {
		t.Fatalf("server got %q, want %q", res.data, msg)
	}
	if !bytes.Equal(ack, reply) {
		t.Fatalf("client got %q, want %q", ack, reply)
	}
}

func TestRealityDataConnLarge(t *testing.T) {
	t.Parallel()

	secret := []byte("another-secret")
	pubKey := make([]byte, 32)

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	clientConn, _ := NewRealityDataConn(clientRaw, secret, pubKey, true)
	serverConn, _ := NewRealityDataConn(serverRaw, secret, pubKey, false)

	payload := make([]byte, 128*1024) // 128KB
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	// Server receives from client.
	serverDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			serverDone <- nil
			return
		}
		serverDone <- buf
	}()

	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal("client write:", err)
	}

	received := <-serverDone
	if received == nil {
		t.Fatal("server read failed")
	}
	if !bytes.Equal(received, payload) {
		for i, b := range received {
			if b != payload[i] {
				t.Fatalf("mismatch at byte %d: got %d want %d", i, b, payload[i])
			}
		}
	}
}

// discardConn is a net.Conn whose Write discards all bytes immediately,
// isolating the Write framing/encryption cost from any I/O.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (discardConn) Close() error                     { return nil }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkRealityDataConnWrite(b *testing.B) {
	secret := []byte("bench-secret")
	pubKey := make([]byte, 32)

	conn, err := NewRealityDataConn(discardConn{}, secret, pubKey, true)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 16383) // one full max-size record per Write
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}
