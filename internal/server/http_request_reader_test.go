package server

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadHTTPRequestExact_Valid(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	req := "GET /path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Foo: bar\r\n" +
		"\r\n" +
		"BODY-NOT-READ"
	go func() { b.Write([]byte(req)) }()
	a.SetReadDeadline(time.Now().Add(time.Second))

	line, headers, err := readHTTPRequestExact(a, 8192)
	if err != nil {
		t.Fatalf("readHTTPRequestExact: %v", err)
	}
	if line != "GET /path HTTP/1.1" {
		t.Fatalf("requestLine=%q", line)
	}
	if headers["Host"] != "example.com" {
		t.Fatalf("Host header=%q", headers["Host"])
	}
	if headers["X-Foo"] != "bar" {
		t.Fatalf("X-Foo header=%q", headers["X-Foo"])
	}

	// Body bytes must NOT have been consumed — verify by reading.
	bodyBuf := make([]byte, len("BODY-NOT-READ"))
	n, _ := a.Read(bodyBuf)
	if string(bodyBuf[:n]) != "BODY-NOT-READ" {
		t.Fatalf("body got %q (read %d), want BODY-NOT-READ — readHTTPRequestExact over-read past the terminator", bodyBuf[:n], n)
	}
}

func TestReadHTTPRequestExact_TooLarge(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	huge := "GET / HTTP/1.1\r\n" + strings.Repeat("X-Pad: aaaaaaaaaa\r\n", 500) + "\r\n"
	go func() { b.Write([]byte(huge)) }()
	a.SetReadDeadline(time.Now().Add(time.Second))

	if _, _, err := readHTTPRequestExact(a, 1024); err == nil {
		t.Fatalf("expected error on oversize request, got nil")
	}
}

func TestReadHTTPRequestExact_NoTerminator(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		b.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n"))
		b.Close()
	}()
	a.SetReadDeadline(time.Now().Add(time.Second))

	if _, _, err := readHTTPRequestExact(a, 8192); err == nil {
		t.Fatalf("expected error on missing terminator, got nil")
	}
}

func TestReadHTTPRequestExact_TerminatorSplitAcrossReads(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	req := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	go func() {
		for i := 0; i < len(req); i++ {
			b.Write([]byte{req[i]})
		}
	}()
	a.SetReadDeadline(time.Now().Add(2 * time.Second))

	if _, _, err := readHTTPRequestExact(a, 8192); err != nil {
		t.Fatalf("readHTTPRequestExact: %v", err)
	}
}
