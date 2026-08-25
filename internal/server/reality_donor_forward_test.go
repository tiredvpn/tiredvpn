package server

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// The cover-domain path must forward the ClientHello byte for byte.
//
// The transcript hash covers the ClientHello as the client sent it. Change one
// byte on the way to the donor and the donor hashes a different message, so
// Finished never verifies and the client ends the handshake with a decrypt
// error rather than a page. Stripping the padding extension here did exactly
// that: it turned the cover from "no answer" into "bad record mac", which is
// not an improvement for anyone trying to reach the site.
func TestDonorForwardIsByteIdentical(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	old := realityDonorPort
	realityDonorPort = port
	t.Cleanup(func() { realityDonorPort = old })

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, _ := io.ReadAtLeast(c, buf, 5)
		got <- buf[:n]
	}()

	hello := helloWithPadding(t, "www.microsoft.com", 512)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleREALITYUnauthorized(server, hello, "127.0.0.1", testLogger(t))
	}()

	forwarded := <-got
	client.Close()
	server.Close()
	<-done

	if forwarded == nil {
		t.Fatal("the donor never received a connection")
	}
	if !bytes.Equal(forwarded, hello) {
		t.Fatalf("the ClientHello was altered on the way to the donor: sent %d bytes, "+
			"donor got %d; any difference breaks the transcript hash and the client "+
			"fails the handshake with a decrypt error", len(hello), len(forwarded))
	}
}
