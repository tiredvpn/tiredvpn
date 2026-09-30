package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// Issue #93 over a real transport: the relay reaches the exit over TLS + HTTP/2
// stego (UpstreamDialer against the fake exit, which frames exactly like a real
// server), reads the exit's handshake response with the version its client
// sent, and must leave the exit's first tunnel frame intact both when it rides
// in the same stego payload as the response and when it follows 50 ms later,
// inside the window the old reader spent waiting for an optional flags byte.

func relayFirstFrame() []byte {
	pkt := []byte("first-packet")
	f := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(f, uint32(len(pkt)))
	copy(f[4:], pkt)
	return f
}

func expectRelayFirstFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	want := relayFirstFrame()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("first frame after handshake: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("first frame = %x, want %x: stream desynced", got, want)
	}
}

// exitAnswer answers the way a 1.11 exit's h2 path does: the builder output
// for the client's own version, with no port hopping, probe or v6 pool.
func exitAnswer(handshake []byte) []byte {
	hs, _ := splitTUNOrigin(handshake)
	version := byte(0)
	if len(hs) >= 7 {
		version = hs[6]
	}
	return buildTUNHandshakeResponse(version, exitServerIP, exitClientIP, tunHandshakeCaps{}, nil)
}

func TestDialTUNKeepsFirstFrame(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	for _, tc := range []struct {
		name      string
		handshake []byte
		coalesced bool
	}{
		// v3: the exit's h2 path answers with the bare 9 bytes.
		{"v3, frame 50ms after the response", v3TUNHandshake(), false},
		{"v3, frame in the response payload", v3TUNHandshake(), true},
		// v4: the exit always sends the flags byte, here 0x00.
		{"v4, frame 50ms after the response", dialTUNHandshake(), false},
		{"v4, frame in the response payload", dialTUNHandshake(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var exit *fakeTUNExit
			if tc.coalesced {
				exit = startFakeTUNExit(t, secret, func(hs []byte) []byte {
					return append(exitAnswer(hs), relayFirstFrame()...)
				})
			} else {
				exit = startFakeTUNExitThen(t, secret, exitAnswer, relayFirstFrame())
			}

			dialer := NewUpstreamDialer(exit.ln.Addr().String(), secret)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, resp, err := dialer.DialTUN(ctx, tc.handshake, "test-origin")
			if err != nil {
				t.Fatalf("DialTUN: %v", err)
			}
			defer conn.Close()

			if want := exitAnswer(tc.handshake); !bytes.Equal(resp, want) {
				t.Fatalf("resp = %x, want %x", resp, want)
			}
			expectRelayFirstFrame(t, conn)
		})
	}
}

// TestRelayBridgeKeepsFirstFrame chains both readers: the relay reads the
// exit's answer over h2 stego and bridges, the downstream client reads the
// forwarded answer and then the exit's first frame through the bridge.
func TestRelayBridgeKeepsFirstFrame(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	exit := startFakeTUNExitThen(t, secret, exitAnswer, relayFirstFrame())

	srvCtx := newTestServerContext(t)
	srvCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)

	relaySide, clientSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close() })
	go relayTUNToUpstream(relaySide, srvCtx, testLogger(t), v3TUNHandshake())

	if err := clientSide.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	resp, next, err := tun.ReadTUNHandshakeResponse(clientSide, 0x03)
	if err != nil {
		t.Fatalf("read relayed handshake response: %v", err)
	}
	if want := exitAnswer(v3TUNHandshake()); !bytes.Equal(resp, want) {
		t.Fatalf("relayed resp = %x, want %x", resp, want)
	}
	expectRelayFirstFrame(t, next)
}
