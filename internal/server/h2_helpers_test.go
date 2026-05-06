package server

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestReadH2Preface_Valid(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		b.Write([]byte(http2.ClientPreface))
	}()
	a.SetReadDeadline(time.Now().Add(time.Second))
	if err := readH2Preface(a, testLogger(t)); err != nil {
		t.Fatalf("readH2Preface: %v", err)
	}
}

func TestReadH2Preface_Truncated(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		b.Write([]byte(http2.ClientPreface[:10]))
		b.Close()
	}()
	a.SetReadDeadline(time.Now().Add(time.Second))
	if err := readH2Preface(a, testLogger(t)); err == nil {
		t.Fatalf("expected error on truncated preface, got nil")
	}
}

func TestReadH2Preface_Garbage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		b.Write(bytes.Repeat([]byte("x"), len(http2.ClientPreface)))
	}()
	a.SetReadDeadline(time.Now().Add(time.Second))
	if err := readH2Preface(a, testLogger(t)); err == nil {
		t.Fatalf("expected error on garbage preface, got nil")
	}
}

func TestNewH2Framer_WritesSettings(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	settingsCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		settingsCh <- buf[:n]
	}()

	framer, err := newH2Framer(a, testLogger(t))
	if err != nil {
		t.Fatalf("newH2Framer: %v", err)
	}
	if framer == nil {
		t.Fatalf("framer is nil")
	}

	select {
	case got := <-settingsCh:
		// HTTP/2 SETTINGS frame: 9-byte header, type=4 at offset 3
		if len(got) < 9 || got[3] != 0x04 {
			t.Fatalf("expected SETTINGS frame (type 0x04 at offset 3), got % x", got)
		}
	case <-time.After(time.Second):
		t.Fatalf("newH2Framer did not write SETTINGS within 1s")
	}
}
