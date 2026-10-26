package server

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// Two clients behind one NAT, through a real relay into a real exit. The
// relay told the exit only the client's IP (the TRO1 trailer), and that IP
// is the public one both share, so both ended up on the lease
// "global@<public ip>": the exit handed them one tunnel address and they
// took it from each other every half minute. This is the field case behind
// the msk relays - a home router and a phone.
//
// The relay now also tells the exit which of its clients this is (TRC1), so
// the two hold two leases. On a shared credential the tag is drawn per
// session, which is what these clients have; a client with its own
// credential gets its own id and keeps its address.

// natClient is one client behind the NAT: a real VPNClient through the
// relay, with the tunnel address the exit gave it.
func natClient(t *testing.T, relay string, secret []byte) *tun.VPNClient {
	t.Helper()
	return clientVia(t, relay, true, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewAntiProbeStrategy(m, secret)
	})
}

// TestTwoClientsBehindOneNATGetTwoLeases runs both clients through one relay
// into one exit with an IP pool, and requires two tunnel addresses that stay
// put: on one lease the second client took the first one's address and the
// exit logged the takeover.
func TestTwoClientsBehindOneNATGetTwoLeases(t *testing.T) {
	scaleLegClocks(t)
	out := captureLog(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)

	first := natClient(t, relay, secret)
	firstIP := first.LocalIP()
	second := natClient(t, relay, secret)
	secondIP := second.LocalIP()
	if firstIP == nil || secondIP == nil {
		t.Fatalf("no tunnel address: %v, %v", firstIP, secondIP)
	}
	if firstIP.Equal(secondIP) {
		t.Fatalf("both clients behind one address got %s, and will evict each other:\n%s", firstIP, out.String())
	}
	// Both sessions have to be live at once: the exit must hold two clients,
	// not have replaced one with the other.
	for _, tc := range []struct {
		name   string
		client *tun.VPNClient
	}{{"first", first}, {"second", second}} {
		w := exitWriterFor(t, exit, tc.client.LocalIP())
		pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), tc.client.LocalIP())
		pkt[3] = byte(len(pkt))
		if err := w.SendPacket(pkt); err != nil {
			t.Fatalf("%s client: %v", tc.name, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, down, _, _ := tc.client.Stats(); down > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("nothing reached the %s client at %s:\n%s", tc.name, tc.client.LocalIP(), out.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if strings.Contains(out.String(), "Taking over") || strings.Contains(out.String(), "takeover") {
		t.Fatalf("the exit replaced one client with the other:\n%s", out.String())
	}
}

// TestARelayTellsTheExitWhichClientItIs is the unit of the same thing: the
// setup payload a relay forwards carries the client tag, before the origin
// trailer, and both come back out; an exit that reads neither sees the
// handshake it has always seen.
func TestARelayTellsTheExitWhichClientItIs(t *testing.T) {
	handshake := []byte{10, 8, 0, 2, 0x05, 0xdc, 0x03}
	setup := appendTUNClientTag(handshake, "cdenis-phone")
	setup = appendTUNOrigin(setup, "203.0.113.7")

	rest, origin := splitTUNOrigin(setup)
	rest, tag := splitTUNClientTag(rest)
	if origin != "203.0.113.7" || tag != "cdenis-phone" || string(rest) != string(handshake) {
		t.Fatalf("origin %q, tag %q, handshake %x", origin, tag, rest)
	}
	// An old exit reads the seven fixed bytes and ignores the rest.
	if string(setup[:len(handshake)]) != string(handshake) {
		t.Fatalf("the fixed handshake moved: %x", setup[:len(handshake)])
	}
	// An old relay sends no tag: the payload parses as before.
	old := appendTUNOrigin(handshake, "203.0.113.7")
	rest, origin = splitTUNOrigin(old)
	rest, tag = splitTUNClientTag(rest)
	if origin != "203.0.113.7" || tag != "" || string(rest) != string(handshake) {
		t.Fatalf("old relay: origin %q, tag %q, handshake %x", origin, tag, rest)
	}
}

// TestALeaseIsKeyedByTheRelaysClientTag: two clients on one shared
// credential and one origin get two lease keys, and a client with its own
// credential keeps its own key whatever tag a relay sends.
func TestALeaseIsKeyedByTheRelaysClientTag(t *testing.T) {
	shared := sharedIdentity(globalClientID)
	a := allocationKey(shared, "203.0.113.7", "s0123456789abcdef")
	b := allocationKey(shared, "203.0.113.7", "sfedcba9876543210")
	if a == b {
		t.Fatalf("two clients behind one address share the key %q", a)
	}
	if !strings.HasPrefix(a, globalClientID+"@203.0.113.7#") {
		t.Fatalf("the key %q is not the origin key with a tag", a)
	}
	if got := allocationKey(shared, "203.0.113.7", ""); got != globalClientID+"@203.0.113.7" {
		t.Fatalf("without a tag the key is %q, want what an old relay got", got)
	}
	named := registryIdentity("denis-phone")
	if got := allocationKey(named, "203.0.113.7", "cdenis-phone"); got != "denis-phone" {
		t.Fatalf("a client with its own credential is keyed %q", got)
	}
}

// TestTheRelaysTagIsStableForAKnownClientAndDrawnOtherwise: a client the
// relay knows by its own credential gets a tag of its id, the same on every
// session, so its address survives a reconnect; clients on a shared
// credential get a drawn one, because nothing they send tells them apart.
func TestTheRelaysTagIsStableForAKnownClientAndDrawnOtherwise(t *testing.T) {
	named := registryIdentity("denis-phone")
	if a, b := relayClientTag(named), relayClientTag(named); a != b || !strings.HasSuffix(a, "denis-phone") {
		t.Fatalf("a known client's tag is %q then %q", a, b)
	}
	shared := sharedIdentity(globalClientID)
	a, b := relayClientTag(shared), relayClientTag(shared)
	if a == b || a == "" {
		t.Fatalf("two sessions on the shared secret drew the same tag %q", a)
	}
	// A relay that cannot name its client at all still draws one, rather
	// than falling back to the shared key.
	if relayClientTag(clientIdentity{}) == "" {
		t.Fatal("no tag at all for an unnamed client")
	}
}

// natClientAsking is natClient asking the exit for ask, as a client's
// reconnect asks for the address it holds.
func natClientAsking(t *testing.T, relay string, secret []byte, ask net.IP) *tun.VPNClient {
	t.Helper()
	return clientAskingVia(t, relay, ask, func(m *strategy.Manager) strategy.Strategy {
		return strategy.NewAntiProbeStrategy(m, secret)
	})
}

// clientAskingVia is natClientAsking on the transport make makes.
func clientAskingVia(t *testing.T, relay string, ask net.IP, make func(*strategy.Manager) strategy.Strategy) *tun.VPNClient {
	t.Helper()
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "relay", V4: relay}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(make(m))
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := newTunApp(fds[1])
	t.Cleanup(app.close)
	client, err := tun.NewVPNClient(tun.VPNConfig{TunFd: fds[0], TunName: "nat0", MTU: 1500,
		LocalIP: ask, RemoteIP: net.IPv4(10, 8, 7, 1), ServerAddr: relay, Manager: m,
		IPv6Policy: tun.IPv6PolicyOff, NoStrategyUpgrade: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(client.Stop)
	return client
}

// TestASharedSecretClientKeepsItsAddressAcrossAReconnect is the fix14 stand
// finding (twocli shared) and P2-2 of the round-10 review: through a relay,
// a client on the global secret got a new tunnel address on every
// reconnect. The relay draws its tag per session, and the lease from the
// session before still held the address the reconnect asked for. Round 15
// handed it over only once no session held it, and real reconnects come
// while one still does - a make-before-break upgrade always. Here the
// reconnect asks while the first session is up, takes the address and the
// downlink with it; a later one after a clean stop gets it as well.
func TestASharedSecretClientKeepsItsAddressAcrossAReconnect(t *testing.T) {
	scaleLegClocks(t)
	out := captureLog(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)

	// The session before: a bare TUN session through the relay, with no
	// reconnect of its own - a client that moves to a new session leaves
	// its old one, it does not dial it again.
	oldConn, held := rawTUNSession(t, relay, secret, net.IPv4(10, 8, 7, 60))
	defer oldConn.Close()
	if held == nil || !exit.srvCtx.sharedTUN.Serving(held) {
		t.Fatalf("the first session has no address the exit serves: %v", held)
	}
	again := natClientAsking(t, relay, secret, held)
	if got := again.LocalIP(); !got.Equal(held) {
		t.Fatalf("a reconnect made while the first session is up got %s, want %s:\n%s", got, held, out.String())
	}
	w := exitWriterFor(t, exit, held)
	pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), held)
	pkt[3] = byte(len(pkt))
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = w.SendPacket(pkt)
		if _, down, _, _ := again.Stats(); down > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the downlink to %s did not reach the reconnect:\n%s", held, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	again.Stop()
	for exit.srvCtx.sharedTUN.Serving(held) && time.Now().Before(deadline.Add(10*time.Second)) {
		time.Sleep(10 * time.Millisecond)
	}
	if exit.srvCtx.sharedTUN.Serving(held) {
		t.Fatal("the exit still serves the address - the test proves nothing")
	}
	last := natClientAsking(t, relay, secret, held)
	if got := last.LocalIP(); !got.Equal(held) {
		t.Fatalf("the reconnect after a clean stop got %s, want %s:\n%s", got, held, out.String())
	}
}

// TestARelayedClientDoesNotTakeADirectClientsLiveAddress is P2-5 of the
// round-10 review: a client on the global secret straight to the exit holds
// its address under "global@<origin>", which is also what a relayed client
// at the same origin finds among its legacy keys. Adopting it gave the
// relayed client the direct one's address while it was in use, and the
// downlink with it.
func TestARelayedClientDoesNotTakeADirectClientsLiveAddress(t *testing.T) {
	scaleLegClocks(t)
	out := captureLog(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)

	direct := natClientAsking(t, exit.addr, secret, net.IPv4(10, 8, 7, 70))
	if got := direct.LocalIP(); !got.Equal(net.IPv4(10, 8, 7, 70)) {
		t.Fatalf("the direct client got %s, asked for 10.8.7.70", got)
	}
	relayed := natClientAsking(t, relay, secret, net.IPv4(10, 8, 7, 80))
	if got := relayed.LocalIP(); got.Equal(direct.LocalIP()) {
		t.Fatalf("the relayed client took the direct client's live address %s:\n%s", got, out.String())
	}
	if !exit.srvCtx.sharedTUN.Serving(direct.LocalIP()) {
		t.Fatal("the exit no longer serves the direct client")
	}
}

// TestTwinsAskingForThePoolsFirstAddressGetTwo is P1-1 of the round-11
// review: two boxes on one secret behind one NAT, both asking for the
// address the pool hands out first - the client's default -tun-ip with the
// documented pool, and what Android's "auto" resolves to. The first was
// refused as asked and got the same address from the pool; the second's
// request then named a lease under the drawn-tag prefix and took it from
// the live first, which went on without a downlink. Both must get an
// address of their own and keep it.
func TestTwinsAskingForThePoolsFirstAddressGetTwo(t *testing.T) {
	scaleLegClocks(t)
	out := captureLog(t)
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	relay := legRelay(t, secret, exit)
	first := net.IPv4(10, 8, 7, 2) // the pool's first free address

	a := natClientAsking(t, relay, secret, first)
	b := natClientAsking(t, relay, secret, first)
	if a.LocalIP().Equal(b.LocalIP()) {
		t.Fatalf("both boxes got %s:\n%s", a.LocalIP(), out.String())
	}
	if strings.Contains(out.String(), "taken over") {
		t.Fatalf("a lease was taken over between the twins:\n%s", out.String())
	}
	for _, c := range []*tun.VPNClient{a, b} {
		w := exitWriterFor(t, exit, c.LocalIP())
		pkt := ipv4Packet(net.IPv4(10, 8, 7, 9), c.LocalIP())
		pkt[3] = byte(len(pkt))
		deadline := time.Now().Add(5 * time.Second)
		for {
			_ = w.SendPacket(pkt)
			if _, down, _, _ := c.Stats(); down > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no downlink reached the box at %s:\n%s", c.LocalIP(), out.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// TestADisplacedH2TUNSessionEnds is the exit half of P1-1 and P2-1 of the
// round-11 review: a session whose address a later session took over kept
// running on the HTTP/2 Stego path - its frame loop never looked at the
// registration, and it echoed the client's keepalives - so its client sat
// on a tunnel with no downlink and never reconnected. The exit has to end
// it. Two HTTP/2 Stego clients straight to the exit on one key, one
// address; real clocks, so no read deadline ends it instead.
func TestADisplacedH2TUNSessionEnds(t *testing.T) {
	secret := []byte("relay-leg-secret-0123456789abcdef")
	exit := newLegExit(t, secret)
	ask := net.IPv4(10, 8, 7, 66)
	h2 := func(m *strategy.Manager) strategy.Strategy { return strategy.NewHTTP2StegoStrategy(m, secret, "") }
	first := clientAskingVia(t, exit.addr, ask, h2)
	if !first.LocalIP().Equal(ask) {
		t.Fatalf("the first client got %s", first.LocalIP())
	}
	before := exit.ended.Load()
	second := clientAskingVia(t, exit.addr, ask, h2)
	if !second.LocalIP().Equal(ask) {
		t.Fatalf("the second client got %s, want the same lease %s", second.LocalIP(), ask)
	}
	deadline := time.Now().Add(3 * time.Second)
	for exit.ended.Load() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if exit.ended.Load() == before {
		t.Fatal("the displaced session is still running 3 s after its address was taken over")
	}
}

// rawTUNSession opens a TUN session through relay with anti-probe and a
// bare handshake asking for ask, and returns its conn and the address the
// exit gave it. Nothing reconnects it.
func rawTUNSession(t *testing.T, relay string, secret []byte, ask net.IP) (net.Conn, net.IP) {
	t.Helper()
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "relay", V4: relay}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	s := strategy.NewAntiProbeStrategy(m, secret)
	m.Register(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	hs := []byte{0x02, 0, 0, 0, 0, 0x05, 0xdc, 0x03}
	copy(hs[1:5], ask.To4())
	if _, err := conn.Write(hs); err != nil {
		t.Fatal(err)
	}
	resp, next, err := tun.ReadTUNHandshakeResponse(conn, 0x03, time.Now().Add(5*time.Second))
	if err != nil || len(resp) < 9 || resp[0] != 0 {
		t.Fatalf("handshake: %x %v", resp, err)
	}
	go func() { _, _ = io.Copy(io.Discard, next) }()
	return conn, net.IP(resp[5:9])
}
