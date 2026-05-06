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
