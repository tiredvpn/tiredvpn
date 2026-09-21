package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestClassifyError pins the error-label table the reconnect metrics feed on.
// The label is best-effort, but the ordering matters: "no route" and
// "unreachable" are checked before "network is down", so an ENETUNREACH string
// ("network is unreachable") lands on no_route, not network_down. The test
// spells that out rather than leaving it to accident.
func TestClassifyError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"i/o timeout", errors.New("dial tcp: i/o timeout"), "timeout"},
		{"context deadline", errors.New("context deadline exceeded"), "timeout"},
		{"refused", errors.New("dial tcp 1.2.3.4:995: connect: connection refused"), "refused"},
		{"no route to host", errors.New("connect: no route to host"), "no_route"},
		{"network unreachable maps to no_route", errors.New("connect: network is unreachable"), "no_route"},
		{"network down", errors.New("write: network is down"), "network_down"},
		{"no network sentinel", errors.New("no network available"), "network_down"},
		{"strategies exhausted", errors.New("all strategies failed"), "strategies_exhausted"},
		{"circuit breaker", errors.New("circuit open, refusing dial"), "circuit_breaker"},
		{"EOF", errors.New("unexpected EOF"), "connection_reset"},
		{"reset by peer", errors.New("read: connection reset by peer"), "connection_reset"},
		{"unknown", errors.New("something else entirely"), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyError(tc.err); got != tc.want {
				t.Errorf("classifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// errnoIsOnly matches target under errors.Is but carries a message that shares
// no substring with the string fallback. It isolates the errors.Is branch of
// isTemporaryError: on Linux syscall.EAGAIN.Error() is literally "resource
// temporarily unavailable", so a plain wrapped EAGAIN is caught by the string
// check too and does not prove the errno branch runs. This one can only pass
// through errors.Is.
type errnoIsOnly struct{ target error }

func (e errnoIsOnly) Error() string        { return "opaque non-blocking condition" }
func (e errnoIsOnly) Is(target error) bool { return target == e.target }

// TestIsTemporaryError covers the EAGAIN/EWOULDBLOCK detection the non-blocking
// TUN read loop uses to tell "no data yet" from a real read error. The
// errors.Is branch and the string fallback are exercised independently: the
// "errno-only, no matching string" case fails unless the errors.Is branch is
// live, and the string cases fail unless the fallback is. A positive control (a
// real errno) sits next to the negative (a plain error).
func TestIsTemporaryError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EAGAIN errno", syscall.EAGAIN, true},
		{"EWOULDBLOCK errno", syscall.EWOULDBLOCK, true},
		{"wrapped EAGAIN", fmt.Errorf("tun read: %w", syscall.EAGAIN), true},
		{"errno-only, no matching string", errnoIsOnly{target: syscall.EAGAIN}, true},
		{"resource temporarily unavailable string", errors.New("read: resource temporarily unavailable"), true},
		{"would block string", errors.New("socket would block"), true},
		{"real error is not temporary", errors.New("connection reset by peer"), false},
		{"EPERM is not temporary", syscall.EPERM, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTemporaryError(tc.err); got != tc.want {
				t.Errorf("isTemporaryError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestAddJitter checks the bound, not the shape: with factor 0.3 the result
// must stay inside [0.7d, 1.3d] for every draw, and never go negative (a
// negative backoff would busy-loop the reconnect). Distribution is deliberately
// not asserted - see verification rule 3; only the envelope is a property.
func TestAddJitter(t *testing.T) {
	const d = 1000 * time.Millisecond
	lo := time.Duration(float64(d) * 0.7)
	hi := time.Duration(float64(d) * 1.3)
	for i := 0; i < 10000; i++ {
		got := addJitter(d)
		if got < lo || got > hi {
			t.Fatalf("addJitter(%v) = %v, outside [%v, %v]", d, got, lo, hi)
		}
		if got < 0 {
			t.Fatalf("addJitter(%v) = %v is negative", d, got)
		}
	}
	if got := addJitter(0); got != 0 {
		t.Errorf("addJitter(0) = %v, want 0", got)
	}
}

// TestReadTUNHandshakeResponseRelayPath exercises the exported relay entry
// point, which reads with clientVersion 0 ("unknown", forwarding a response
// whose downstream client it cannot see). Every dual-stack shape must be read
// whole across arbitrary segmentation and its v6 block must decode - a byte
// left in the stream would be forwarded to the client mid-frame and desync it.
func TestReadTUNHandshakeResponseRelayPath(t *testing.T) {
	_, server6, client6 := dualBlock()
	for name, payload := range dualResponses() {
		t.Run(name, func(t *testing.T) {
			// One piece, and split at every interior boundary.
			for k := 0; k < len(payload); k++ {
				var conn net.Conn
				if k == 0 {
					conn = chunkedConn(t, payload)
				} else {
					conn = chunkedConn(t, payload, k)
				}
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("split %d: set deadline: %v", k, err)
				}
				resp, err := ReadTUNHandshakeResponse(conn)
				if err != nil {
					t.Fatalf("split %d: ReadTUNHandshakeResponse: %v", k, err)
				}
				if !bytes.Equal(resp, payload) {
					t.Fatalf("split %d: resp = %x, want %x (tail left in stream)", k, resp, payload)
				}
				caps, ok := ParseTUNHandshakeCapabilities(resp)
				if !ok || !caps.DualStackEnabled {
					t.Fatalf("split %d: dual-stack not decoded from relayed response: %+v ok=%v", k, caps, ok)
				}
				if !caps.ServerIP6.Equal(server6) || !caps.ClientIP6.Equal(client6) {
					t.Errorf("split %d: v6 addrs = %s/%s, want %s/%s", k, caps.ServerIP6, caps.ClientIP6, server6, client6)
				}
			}
		})
	}
}

// TestReadTUNHandshakeResponseLegacy9Byte confirms the relay path returns the
// bare 9-byte form intact when the exit predates the flags byte: the exit sends
// nothing past byte 9, so the read must bound the peek and return exactly those
// nine bytes rather than hang.
func TestReadTUNHandshakeResponseLegacy9Byte(t *testing.T) {
	payload := append([]byte{}, handshakeBase...)
	conn := chunkedConn(t, payload)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	resp, err := ReadTUNHandshakeResponse(conn)
	if err != nil {
		t.Fatalf("ReadTUNHandshakeResponse: %v", err)
	}
	if !bytes.Equal(resp, payload) {
		t.Fatalf("resp = %x, want %x", resp, payload)
	}
	if caps, ok := ParseTUNHandshakeCapabilities(resp); ok {
		t.Errorf("a 9-byte response advertises no capabilities, got %+v ok=%v", caps, ok)
	}
}

// TestGetServerCapabilities pins the accessor to the stored value, including the
// deep-copied v6 address slices carried across the handshake boundary.
func TestGetServerCapabilities(t *testing.T) {
	want := ServerCapabilities{
		MTUProbeSupported: true,
		DualStackEnabled:  true,
		ServerIP6:         net.ParseIP("fd00:10:8::1"),
		ClientIP6:         net.ParseIP("fd00:10:8::a08:2"),
	}
	v := &VPNClient{serverCaps: want}
	got := v.GetServerCapabilities()
	if got.MTUProbeSupported != want.MTUProbeSupported || got.DualStackEnabled != want.DualStackEnabled {
		t.Errorf("flags = %+v, want %+v", got, want)
	}
	if !got.ServerIP6.Equal(want.ServerIP6) || !got.ClientIP6.Equal(want.ClientIP6) {
		t.Errorf("v6 addrs = %s/%s, want %s/%s", got.ServerIP6, got.ClientIP6, want.ServerIP6, want.ClientIP6)
	}
}
