package server

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// TestReassembleSSHCarrierFragmented pins problem 1: a confusion SSH carrier
// whose first flight arrives split across writes must be reassembled and
// classified as confusion, not mistaken for the bare-banner ssh_camouflage
// client and pushed into a handshake it would fail (a decoy and a retry). The
// banner arrives first and alone - the worst split - and the rest a moment
// later, the way a single Write fragmented across TCP segments does.
func TestReassembleSSHCarrierFragmented(t *testing.T) {
	srvCtx := camouflageCtx(t)
	carrier := buildConfusionSSHCarrier(t, []byte(camouflageTestSecret))

	nl := bytes.Index(carrier, []byte("\r\n"))
	if nl < 0 {
		t.Fatal("carrier has no banner terminator")
	}
	peek := carrier[:nl+2] // just the banner, as a first segment might carry
	rest := carrier[nl+2:]

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		time.Sleep(20 * time.Millisecond)
		client.Write(rest)
	}()

	got := reassembleSSHCarrierPeek(server, peek, log.WithPrefix("test"))
	if !bytes.Equal(got, carrier) {
		t.Fatalf("reassembled %d bytes, want the whole %d-byte carrier", len(got), len(carrier))
	}
	if DetectSSHCamouflage(got, srvCtx) {
		t.Error("reassembled carrier classified as camouflage; a fragmented carrier would fall into a failing handshake and a decoy")
	}
}

// TestReassembleSSHCarrierBareBannerNotHeld is the control for problem 1: the
// ssh_camouflage (S2) client sends only its banner and then waits for the
// server. Reassembly must wait out the short window rather than the 10s auth
// timeout, and return the banner unchanged for the camouflage path.
func TestReassembleSSHCarrierBareBannerNotHeld(t *testing.T) {
	srvCtx := camouflageCtx(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// The S2 client sends nothing after its banner: client stays silent.

	banner := []byte(strategy.SSHBanner)
	start := time.Now()
	got := reassembleSSHCarrierPeek(server, banner, log.WithPrefix("test"))
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("bare banner held for %v; the S2 client must not wait the confusion auth timeout", elapsed)
	}
	if !bytes.Equal(got, banner) {
		t.Errorf("returned %d bytes, want the banner unchanged (%d)", len(got), len(banner))
	}
	if !DetectSSHCamouflage(got, srvCtx) {
		t.Error("bare banner not classified as camouflage")
	}
	// It must have actually waited for the possibly-fragmented remainder, not
	// decided on the incomplete peek - which is the bug this replaces.
	if elapsed < sshCarrierReassembleTimeout/2 {
		t.Errorf("returned after %v, expected to wait about the reassembly window %v", elapsed, sshCarrierReassembleTimeout)
	}
}
