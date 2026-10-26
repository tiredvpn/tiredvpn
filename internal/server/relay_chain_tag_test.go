package server

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestAMiddleHopPassesTheClientTagOn is P3-1 of the round-10 review: a
// relay that serves another relay's upstream leg on its HTTP/2 Stego path
// stripped the tag the first relay attached for its client and sent one of
// its own - a new drawn tag on every session for a shared credential, and
// the hop's identity instead of a registry client's stable "c<id>". The
// exit has to see the first relay's tag and origin.
func TestAMiddleHopPassesTheClientTagOn(t *testing.T) {
	secret := []byte("relay-dualstack-test-secret-32b!")
	got := make(chan [2]string, 1)
	exit := startFakeTUNExit(t, secret, func(handshake []byte) []byte {
		hs, origin := splitTUNOrigin(handshake)
		hs, tag := splitTUNClientTag(hs)
		got <- [2]string{tag, origin}
		version := byte(0)
		if len(hs) >= 7 {
			version = hs[6]
		}
		return buildTUNHandshakeResponse(version, exitServerIP, exitClientIP, tunHandshakeCaps{}, nil)
	})

	relayCtx := newTestServerContext(t)
	relayCtx.cfg.Secret = secret
	relayCtx.upstreamDialer = NewUpstreamDialer(exit.ln.Addr().String(), secret)
	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relayLn.Close() })
	go func() {
		conn, err := relayLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		logger := testLogger(t)
		if err := readH2Preface(conn, logger); err != nil {
			return
		}
		framer, err := newH2Framer(conn, logger)
		if err != nil {
			return
		}
		var authenticated, connTracked bool
		var authClientID clientIdentity
		var authSecret []byte
		var tunnel *h2TunnelState
		runH2FrameLoop(&conn, &framer, hpack.NewDecoder(4096, nil), relayCtx, logger, &authenticated, &authClientID,
			&authSecret, &connTracked, &tunnel, nil, pipeTestEKM)
	}()

	// The first relay of the chain, as it writes up its leg: the client's
	// handshake, its tag, its origin.
	clientConn, err := net.Dial("tcp", relayLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientConn.Close() })
	up := strategy.NewHTTP2StegoConn(clientConn, secret, true, strategy.NaivePaddingMinimal, pipeTestEKM)
	if err := up.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	const tag, origin = "sfeedfacecafebeef", "203.0.113.9"
	setup := append([]byte{0x02}, appendTUNOrigin(appendTUNClientTag(dialTUNHandshake(), tag), origin)...)
	if _, err := up.Write(setup); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := tun.ReadTUNHandshakeResponse(up, dialTUNHandshake()[6], time.Time{}); err != nil {
		t.Fatalf("response: %v", err)
	}
	select {
	case g := <-got:
		if g[0] != tag || g[1] != origin {
			t.Fatalf("the exit got tag %q and origin %q, want %q and %q", g[0], g[1], tag, origin)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the exit saw no handshake")
	}
}
