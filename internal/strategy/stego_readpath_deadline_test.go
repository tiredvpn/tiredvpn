package strategy

import (
	stdtls "crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestAOneWayDownloadDoesNotBreakTheStegoConn is P2-1 of the round-7 review
// at the client's end, through HTTP2StegoConn's own Read and Write over TLS.
// The tunnel sets a write deadline before each write it makes and never
// clears it; on a download with nothing going up, the WINDOW_UPDATE flush the
// read path makes every 256 KB ran into that old deadline. The write failed,
// tls.Conn made the failure permanent, and the next write the tunnel made -
// a keepalive, a packet - failed too.
func TestAOneWayDownloadDoesNotBreakTheStegoConn(t *testing.T) {
	secret := []byte("stego-readpath-secret")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const download = 1 << 20
	got := make(chan []byte, 1)
	srvErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer raw.Close()
		tlsConn, err := serverTLS(t, raw)
		if err != nil {
			srvErr <- err
			return
		}
		s := NewHTTP2StegoConn(tlsConn, secret, false, NaivePaddingMinimal, nil)
		if err := s.Handshake(); err != nil {
			srvErr <- err
			return
		}
		chunk := make([]byte, 1000)
		for sent := 0; sent < download; sent += len(chunk) {
			if _, err := s.Write(chunk); err != nil {
				srvErr <- err
				return
			}
		}
		buf := make([]byte, 64)
		n, err := s.Read(buf)
		if err != nil {
			srvErr <- err
			return
		}
		got <- buf[:n]
		srvErr <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tlsConn := stdtls.Client(raw, &stdtls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // a test peer
	c := NewHTTP2StegoConn(tlsConn, secret, true, NaivePaddingMinimal, nil)
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// The tunnel's last write before the download: a deadline that runs out
	// long before the download is over.
	_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	time.Sleep(100 * time.Millisecond)
	if _, err := io.ReadFull(c, make([]byte, download)); err != nil {
		t.Fatalf("the download broke off: %v", err)
	}

	// The next write the tunnel makes, with a fresh deadline of its own.
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("after the download")); err != nil {
		t.Fatalf("the first write after a one-way download failed: %v", err)
	}
	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server read nothing after the download")
	}
	if b := <-got; string(b) != "after the download" {
		t.Fatalf("the server read %q", b)
	}
}
