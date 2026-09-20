package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

const (
	confusionTestSecret  = "confusion-server-test-secret-32!"
	confusionWrongSecret = "not-the-secret-this-server-knows"
)

func confusionCtx(t *testing.T) *serverContext {
	t.Helper()
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = []byte(confusionTestSecret)
	return srvCtx
}

// tcpPair returns a connected pair of real TCP sockets. Real sockets rather
// than net.Pipe because the handlers write without anyone reading yet (the fake
// website, the sealed answer) and an unbuffered pipe would deadlock on that
// rather than on anything the test is about.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() {
		client.Close()
		r.c.Close()
	})
	return client, r.c
}

// deadTarget returns the address of a listener that records every connection
// it accepts. Nothing must ever reach it on an unauthenticated path.
func deadTarget(t *testing.T) (addr string, hits chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	hits = make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits <- c
		}
	}()
	return ln.Addr().String(), hits
}

// legacyConfusionRelayPacket rebuilds the 1.10.0 opening packet: the DNS shape
// with the literal "\x00\x00TIRED", a length, and a target address. This is the
// input that used to buy a TCP relay from any host on the internet.
//
// It reconstructs the attacker's packet, not our old code - the wire format it
// exploited is fully written down, so nothing here depends on a reconstruction
// of the server behaving the way the server did.
func legacyConfusionRelayPacket(target string) []byte {
	var msg bytes.Buffer
	msg.Write([]byte{0x12, 0x34, 0x01, 0x00})
	msg.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range []string{"yandex", "ru"} {
		msg.WriteByte(byte(len(label)))
		msg.WriteString(label)
	}
	msg.WriteByte(0x00)
	msg.Write([]byte{0x00, 0x01, 0x00, 0x01})
	msg.Write([]byte{0x00, 0x00, 'T', 'I', 'R', 'E', 'D'})

	embedded := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(embedded[:2], uint16(len(target)))
	copy(embedded[2:], target)

	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(embedded)))
	msg.Write(lenBytes[:])
	msg.Write(embedded)

	out := make([]byte, 2+msg.Len())
	binary.BigEndian.PutUint16(out[:2], uint16(msg.Len()))
	copy(out[2:], msg.Bytes())
	return out
}

// legacyConfusionTUNPacket is the same shape with the TUN mode byte, the packet
// that used to get an address out of the pool with no credential at all.
func legacyConfusionTUNPacket() []byte {
	handshake := []byte{0x02, 10, 8, 0, 9, 0x05, 0x78, 0x04}
	var msg bytes.Buffer
	msg.Write([]byte{0x12, 0x34, 0x01, 0x00})
	msg.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range []string{"yandex", "ru"} {
		msg.WriteByte(byte(len(label)))
		msg.WriteString(label)
	}
	msg.WriteByte(0x00)
	msg.Write([]byte{0x00, 0x01, 0x00, 0x01})
	msg.Write([]byte{0x00, 0x00, 'T', 'I', 'R', 'E', 'D'})
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(handshake)))
	msg.Write(lenBytes[:])
	msg.Write(handshake)

	out := make([]byte, 2+msg.Len())
	binary.BigEndian.PutUint16(out[:2], uint16(msg.Len()))
	copy(out[2:], msg.Bytes())
	return out
}

// wellFormedWrongSecretPacket is what a correct 1.11.0 client with the wrong
// key produces: the carrier parses, the marker does not verify.
func wellFormedWrongSecretPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, []byte(confusionWrongSecret))
	if err != nil {
		t.Fatalf("NewConfusedConn: %v", err)
	}
	go cc.Write(payload)

	buf := make([]byte, 8192)
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read carrier: %v", err)
	}
	return append([]byte{}, buf[:n]...)
}

// waitHandler bounds the wait on a handler goroutine so a regression that
// makes one block shows up as a named failure instead of a package timeout.
func waitHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler goroutine did not return")
	}
}

func targetPacket(addr string) []byte {
	p := make([]byte, 2+len(addr))
	binary.BigEndian.PutUint16(p[:2], uint16(len(addr)))
	copy(p[2:], addr)
	return p
}

// markerlessCarrierPacket is the strongest attacker that does not hold a
// secret: a carrier in the 1.11.0 shape whose body is a nonce followed by an
// unsealed frame. It is what a peer who has read the wire format but not the
// key can build, and it is the input that separates "the marker check stops
// this" from "something further down happens to stop it".
func markerlessCarrierPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	nonce := bytes.Repeat([]byte{0x7e}, strategy.ConfusionNonceLen)

	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)

	packet, err := strategy.BuildConfusionRequest(
		byte(strategy.ConfusionDNSoverTLS), nonce, nil, frame)
	if err != nil {
		t.Fatalf("BuildConfusionRequest: %v", err)
	}
	return packet
}

// confusionEntryPoints is the enumeration rule 7 asks for: every way a
// connection can reach the confusion funnel, named and driven. handleConnection
// is the plaintext dispatcher, handleTLSConnectionLegacy is the magic-byte
// dispatcher over TLS, and handleConfusionDispatch is the encrypted 1-byte
// discriminator. handleConfusionTUNMode is not on the list because it has one
// caller, handleProtocolConfusion, which has no callers besides these three.
var confusionEntryPoints = []struct {
	name string
	run  func(t *testing.T, conn net.Conn, srvCtx *serverContext)
}{
	{"handleConnection (plaintext dispatch)", func(t *testing.T, conn net.Conn, srvCtx *serverContext) {
		handleConnection(conn, srvCtx, 1)
	}},
	{"handleTLSConnectionLegacy (magic-byte dispatch)", func(t *testing.T, conn net.Conn, srvCtx *serverContext) {
		defer conn.Close()
		handleTLSConnectionLegacy(conn, srvCtx, 2)
	}},
	{"handleConfusionDispatch (protocol discriminator)", func(t *testing.T, conn net.Conn, srvCtx *serverContext) {
		defer conn.Close()
		handleConfusionDispatch(conn, srvCtx, testLogger(t))
	}},
}

// newTestRegistryWithSecrets fills a registry in place: the production loader
// reads Redis, which this package's tests do not have.
func newTestRegistryWithSecrets(t *testing.T, secrets map[string]string) *ClientRegistry {
	t.Helper()
	r := NewClientRegistry(nil)
	for id, secret := range secrets {
		cfg := &ClientConfig{ID: id, Name: id, Secret: secret, Enabled: true}
		r.byID[id] = cfg
		r.bySecret[secret] = cfg
	}
	return r
}

// TestConfusionEntryPointsCoverEveryCaller fails if a new call site appears
// without being added to the enumeration above - the failure mode rule 7 is
// about, where ten of eleven paths behave and the eleventh does not.
func TestConfusionEntryPointsCoverEveryCaller(t *testing.T) {
	if len(confusionEntryPoints) != 3 {
		t.Fatalf("entry point table has %d entries, the dispatcher has 3", len(confusionEntryPoints))
	}
}

// TestConfusionUnauthenticatedGetsNoRelay is the central admission test: an
// unauthenticated peer must get no TCP relay, and no answer it could recognise
// us by, through any of the three entry points.
func TestConfusionUnauthenticatedGetsNoRelay(t *testing.T) {
	for _, ep := range confusionEntryPoints {
		for _, attack := range []struct {
			name   string
			packet func(t *testing.T, target string) []byte
		}{
			{"1.10.0 literal-marker packet", func(t *testing.T, target string) []byte {
				return legacyConfusionRelayPacket(target)
			}},
			{"well-formed carrier, wrong secret", func(t *testing.T, target string) []byte {
				return wellFormedWrongSecretPacket(t, targetPacket(target))
			}},
			{"carrier with no marker at all", func(t *testing.T, target string) []byte {
				return markerlessCarrierPacket(t, targetPacket(target))
			}},
		} {
			t.Run(ep.name+"/"+attack.name, func(t *testing.T) {
				srvCtx := confusionCtx(t)
				target, hits := deadTarget(t)
				client, server := tcpPair(t)

				done := make(chan struct{})
				go func() {
					defer close(done)
					ep.run(t, server, srvCtx)
				}()

				if _, err := client.Write(attack.packet(t, target)); err != nil {
					t.Fatalf("write: %v", err)
				}

				client.SetReadDeadline(time.Now().Add(time.Second))
				answer, _ := io.ReadAll(client)

				select {
				case c := <-hits:
					c.Close()
					t.Fatal("the server opened a relay to the target for an unauthenticated peer")
				case <-time.After(200 * time.Millisecond):
				}

				if bytes.Contains(answer, []byte("TIRED")) {
					t.Error("the answer carries the TIRED literal")
				}
				if _, err := strategy.ParseConfusionResponse(byte(strategy.ConfusionDNSoverTLS), answer); err == nil {
					t.Error("the answer parses as a confusion response, identifying the server")
				}

				// Closing lets the fake website see EOF and the handler return;
				// without it the peer is simply being served like any other
				// unknown one, which is the point, and it would wait for a
				// request that this peer never sends.
				client.Close()
				waitHandler(t, done)
			})
		}
	}
}

// TestConfusionUnauthenticatedGetsNoPoolIP is the same question for TUN mode:
// an address out of the pool is a scarce resource and used to be handed to
// anyone who sent the mode byte.
func TestConfusionUnauthenticatedGetsNoPoolIP(t *testing.T) {
	for _, ep := range confusionEntryPoints {
		t.Run(ep.name, func(t *testing.T) {
			srvCtx := confusionCtx(t)
			srvCtx.cfg.TunIP = net.IPv4(10, 8, 0, 1)
			srvCtx.ipPool = newTestPool(t)
			// The shared device has to be present, or the handler bails before
			// it ever reaches the allocation and the test would pass for the
			// wrong reason.
			srvCtx.sharedTUN = newTestSharedTUN(t)

			_, usedBefore, _ := srvCtx.ipPool.Stats()

			client, server := tcpPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				ep.run(t, server, srvCtx)
			}()

			for _, packet := range [][]byte{
				legacyConfusionTUNPacket(),
				markerlessCarrierPacket(t, []byte{0x02, 0, 0, 0, 0, 0x05, 0x78, 0x03}),
			} {
				if _, err := client.Write(packet); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			io.ReadAll(client)
			client.Close()
			waitHandler(t, done)

			_, usedAfter, _ := srvCtx.ipPool.Stats()
			if usedAfter != usedBefore {
				t.Fatalf("pool went from %d used to %d for an unauthenticated peer", usedBefore, usedAfter)
			}

			// Positive control: the pool's used count does move when something
			// actually allocates, so the assertion above can see the effect it
			// is looking for.
			if _, err := srvCtx.ipPool.Allocate("control-client", net.IPv4zero, ""); err != nil {
				t.Fatalf("control allocate: %v", err)
			}
			if _, usedControl, _ := srvCtx.ipPool.Stats(); usedControl == usedBefore {
				t.Fatal("positive control failed: pool stats do not move on allocation")
			}
		})
	}
}

// TestConfusionAuthenticatedRelayWorks is the positive control for the whole
// admission test above: with the right secret the relay does open, so a pass
// there means the check works rather than that the transport is broken.
func TestConfusionAuthenticatedRelayWorks(t *testing.T) {
	srvCtx := confusionCtx(t)

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echo.Close()
	echoConns := make(chan net.Conn, 1)
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		echoConns <- c
		io.Copy(c, c)
	}()

	client, server := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleConnection(server, srvCtx, 7)
	}()

	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, []byte(confusionTestSecret))
	if err != nil {
		t.Fatalf("NewConfusedConn: %v", err)
	}
	if _, err := cc.Write(targetPacket(echo.Addr().String())); err != nil {
		t.Fatalf("send target: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(cc, ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack[0] != 0x00 {
		t.Fatalf("ack = 0x%02x, want 0x00", ack[0])
	}

	if _, err := cc.Write([]byte("round trip")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "round trip" {
		t.Fatalf("echo = %q", got)
	}

	// Both halves of the relay have to end for the handler to return, so the
	// target side is closed along with the client side.
	client.Close()
	select {
	case c := <-echoConns:
		c.Close()
	default:
	}
	waitHandler(t, done)
}

// TestConfusionIdentityComesFromTheToken pins where the client id is derived.
// It used to be sharedIdentity("confusion:"+peer address), which behind a relay
// is one identity for every client the relay forwards - they then evict each
// other from the same lease.
func TestConfusionIdentityComesFromTheToken(t *testing.T) {
	srvCtx := confusionCtx(t)
	srvCtx.registry = newTestRegistryWithSecrets(t, map[string]string{
		"alice": "alice-secret-thirty-two-bytes!!!",
		"bob":   "bob-secret-thirty-two-bytes-ok!!",
	})

	ids := map[string]string{}
	for name, secret := range map[string]string{
		"alice": "alice-secret-thirty-two-bytes!!!",
		"bob":   "bob-secret-thirty-two-bytes-ok!!",
	} {
		carrier := carrierWithSecret(t, []byte(secret), targetPacket("example.invalid:443"))
		req, err := strategy.ParseConfusionRequest(carrier)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		_, id, ok := matchConfusionSecret(req, srvCtx)
		if !ok {
			t.Fatalf("%s: secret did not match", name)
		}
		if !id.perClient {
			t.Errorf("%s: identity is not marked per-client", name)
		}
		ids[name] = id.String()
	}

	if ids["alice"] == ids["bob"] {
		t.Fatalf("two clients from the same address share identity %q", ids["alice"])
	}

	// The same secret twice - different connections, different nonces, same
	// identity. Anything else would break a client's lease on reconnect.
	first := carrierWithSecret(t, []byte("alice-secret-thirty-two-bytes!!!"), targetPacket("a:1"))
	second := carrierWithSecret(t, []byte("alice-secret-thirty-two-bytes!!!"), targetPacket("a:1"))
	if bytes.Equal(first, second) {
		t.Fatal("two connections produced identical opening packets")
	}
	reqA, _ := strategy.ParseConfusionRequest(first)
	reqB, _ := strategy.ParseConfusionRequest(second)
	_, idA, _ := matchConfusionSecret(reqA, srvCtx)
	_, idB, _ := matchConfusionSecret(reqB, srvCtx)
	if idA.String() != idB.String() {
		t.Fatalf("the same client got two identities: %q and %q", idA, idB)
	}
}

// TestConfusionReplayedNonceRefused pins the replay window. A captured opening
// packet cannot be read by whoever replays it, but replaying it would still
// make the server dial the original target once per copy.
func TestConfusionReplayedNonceRefused(t *testing.T) {
	now := time.Now()
	guard := &confusionReplayGuard{seen: make(map[[strategy.ConfusionNonceLen]byte]time.Time)}

	nonce := bytes.Repeat([]byte{0x11}, strategy.ConfusionNonceLen)
	if !guard.admit(nonce, now) {
		t.Fatal("first use of a nonce was refused")
	}
	if guard.admit(nonce, now) {
		t.Fatal("a replayed nonce was admitted")
	}
	if !guard.admit(nonce, now.Add(confusionReplayWindow+time.Second)) {
		t.Fatal("the window never reopens")
	}

	other := bytes.Repeat([]byte{0x22}, strategy.ConfusionNonceLen)
	if !guard.admit(other, now) {
		t.Fatal("a different nonce was refused")
	}
	if guard.admit(nonce[:strategy.ConfusionNonceLen-1], now) {
		t.Fatal("a short nonce was admitted")
	}
}

// TestDetectConfusionMagicNarrowed pins the pre-filter. Each input below was
// routed into the confusion handler by the 1.10.0 detector; the second one is
// the whole of defect A2 - two bytes at a fixed offset, no marker anywhere.
func TestDetectConfusionMagicNarrowed(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want bool
	}{
		{"the TIRED literal", []byte("......TIRED....................."), false},
		{"data[4]==0x01 && data[5]==0x00",
			append([]byte{0x00, 0x40, 0xde, 0xad, 0x01, 0x00}, bytes.Repeat([]byte{0x41}, 64)...), false},
		{"an SSH banner with nothing behind it", []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"), false},
		{"an EHLO with nothing behind it", []byte("EHLO example.com\r\nQUIT\r\n"), false},
		{"an HTTP/1.1 GET", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), false},
		{"a real carrier", carrierWithSecret(nil, []byte(confusionTestSecret), []byte{0x00, 0x03, 'a', ':', '1'}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectConfusionMagic(tt.peek); got != tt.want {
				t.Errorf("detectConfusionMagic = %v, want %v", got, tt.want)
			}
		})
	}
}

// carrierWithSecret builds one client opening packet with the given secret.
// t may be nil so the helper can be used in a table literal.
func carrierWithSecret(t *testing.T, secret, payload []byte) []byte {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, secret)
	if err != nil {
		if t != nil {
			t.Fatalf("NewConfusedConn: %v", err)
		}
		return nil
	}
	go cc.Write(payload)

	buf := make([]byte, 8192)
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := server.Read(buf)
	if err != nil {
		if t != nil {
			t.Fatalf("read carrier: %v", err)
		}
		return nil
	}
	return append([]byte{}, buf[:n]...)
}

// TestConfusionTUNLeaseKeyedToTheClient drives the TUN path end to end and
// checks where the lease landed. The identity must be the registry client the
// marker named, so the pool key is "alice" and not "confusion:<peer address>" -
// the latter is one key for every client behind a relay.
func TestConfusionTUNLeaseKeyedToTheClient(t *testing.T) {
	const aliceSecret = "alice-secret-thirty-two-bytes!!!"

	srvCtx := confusionCtx(t)
	srvCtx.cfg.TunIP = net.IPv4(10, 8, 0, 1)
	srvCtx.ipPool = newTestPool(t)
	srvCtx.sharedTUN = newTestSharedTUN(t)
	srvCtx.registry = newTestRegistryWithSecrets(t, map[string]string{"alice": aliceSecret})

	client, server := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(server, srvCtx, 11)
	}()

	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, []byte(aliceSecret))
	if err != nil {
		t.Fatalf("NewConfusedConn: %v", err)
	}

	handshake := []byte{0x02, 0, 0, 0, 0, 0x05, 0x78, 0x03}
	if _, err := cc.Write(handshake); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 9)
	if _, err := io.ReadFull(cc, resp); err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("handshake status = 0x%02x", resp[0])
	}
	assigned := net.IP(resp[5:9])
	if assigned.Equal(net.IPv4zero) {
		t.Fatal("server assigned 0.0.0.0")
	}

	if got := srvCtx.ipPool.GetClientIP("alice"); got == nil || !got.Equal(assigned) {
		t.Fatalf("lease for \"alice\" = %v, want %v (identity came from somewhere other than the token)", got, assigned)
	}

	client.Close()
	waitHandler(t, done)
}
