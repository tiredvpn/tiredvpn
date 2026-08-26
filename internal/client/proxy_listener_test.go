package client

import (
	"bytes"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// captureLog redirects the package logger for the duration of one test. The
// logger is process-global, so these tests must not run in parallel.
var logMu sync.Mutex

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	logMu.Lock()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		logMu.Unlock()
	})
	return buf
}

// claimsListening reports whether the log asserts that something is listening.
// Matched loosely on purpose: any future wording of the claim should still be
// caught by the negative cases below.
func claimsListening(out string) bool {
	return strings.Contains(strings.ToLower(out), "listening")
}

// TestStartProxyDisabledMakesNoListeningClaim: an empty address means the proxy
// is off on purpose. The log must say so once and must not claim a socket.
// This is the ruhop case — the local SOCKS port is deliberately left to another
// process, and the old code still printed "Listening on  (SOCKS5/HTTP)" with an
// empty address.
func TestStartProxyDisabledMakesNoListeningClaim(t *testing.T) {
	buf := captureLog(t)

	l, err := startProxy("", socksProxyLabel)
	if err != nil {
		t.Fatalf("startProxy(\"\"): %v", err)
	}
	if l != nil {
		t.Fatalf("startProxy(\"\") returned a listener on %s, want nil", l.Addr())
	}

	out := buf.String()
	if claimsListening(out) {
		t.Errorf("log claims a socket is listening while the proxy is off: %q", out)
	}
	if !strings.Contains(out, "disabled") {
		t.Errorf("log does not say the proxy is disabled: %q", out)
	}
	if !strings.Contains(out, socksProxyLabel) {
		t.Errorf("log does not name which proxy is off: %q", out)
	}
}

// TestStartProxyFailedMakesNoListeningClaim: the port is taken, so there is no
// socket. The old code had already printed the claim at startup, leaving the
// log asserting both that the proxy listens and that it failed to start.
func TestStartProxyFailedMakesNoListeningClaim(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot take a port to block: %v", err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()

	buf := captureLog(t)

	l, err := startProxy(taken, socksProxyLabel)
	if err == nil {
		l.Close()
		t.Fatalf("startProxy(%s) succeeded on a port already held", taken)
	}
	if l != nil {
		t.Errorf("startProxy returned a listener alongside the error")
	}

	if out := buf.String(); claimsListening(out) {
		t.Errorf("log claims a socket is listening after the listen failed: %q", out)
	}
}

// TestStartProxyListeningReportsBoundAddress: the positive control. Without it
// the two tests above would pass just as well against a function that never
// logs anything at all.
//
// The address logged is the bound one, not the configured string: ":0" and an
// empty host are resolved by the kernel, so the config is not the fact.
func TestStartProxyListeningReportsBoundAddress(t *testing.T) {
	buf := captureLog(t)

	l, err := startProxy("127.0.0.1:0", socksProxyLabel)
	if err != nil {
		t.Fatalf("startProxy: %v", err)
	}
	defer l.Close()

	out := buf.String()
	if !claimsListening(out) {
		t.Fatalf("log does not report the listening socket: %q", out)
	}
	if !strings.Contains(out, l.Addr().String()) {
		t.Errorf("log does not carry the bound address %s: %q", l.Addr(), out)
	}
	if strings.Contains(out, "127.0.0.1:0") {
		t.Errorf("log carries the configured string instead of the bound port: %q", out)
	}
	if strings.Contains(out, "disabled") {
		t.Errorf("log calls a live proxy disabled: %q", out)
	}
}

// TestStartProxyLabelsTheSocket: the two proxies must be distinguishable in the
// log, otherwise a line about one is read as a line about the other.
func TestStartProxyLabelsTheSocket(t *testing.T) {
	buf := captureLog(t)

	l, err := startProxy("127.0.0.1:0", httpProxyLabel)
	if err != nil {
		t.Fatalf("startProxy: %v", err)
	}
	defer l.Close()

	out := buf.String()
	if !strings.Contains(out, httpProxyLabel) {
		t.Errorf("log does not name the HTTP proxy: %q", out)
	}
	if strings.Contains(out, socksProxyLabel) {
		t.Errorf("HTTP proxy logged under the SOCKS label: %q", out)
	}
}
