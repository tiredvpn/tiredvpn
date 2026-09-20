package strategy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

const sshTestSecret = "ssh-camouflage-test-secret-32b!!"

func newSSHTestReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// sshPipe returns a connected pair over loopback TCP. net.Pipe is synchronous
// and unbuffered, so it deadlocks on the back-to-back flights a real SSH
// handshake sends without waiting for a reply; TCP is also what the strategy
// actually runs on.
func sshPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() { client.Close(); got.conn.Close() })
	return client, got.conn
}

// bufConn is a net.Conn that only supports Write; the sealed bytes land in buf.
type bufConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *bufConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

func chachaStreamForTest(key []byte, seq uint64) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(key, sshChaChaNonce(seq))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// recordConn keeps a copy of every byte that crosses the connection so a test
// can inspect the wire the way an observer between the two ends would.
type recordConn struct {
	net.Conn
	mu sync.Mutex
	rx bytes.Buffer
	tx bytes.Buffer
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.rx.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.tx.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// wire returns everything seen in both directions.
func (c *recordConn) wire() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, 0, c.rx.Len()+c.tx.Len())
	out = append(out, c.rx.Bytes()...)
	return append(out, c.tx.Bytes()...)
}

func (c *recordConn) sent() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.tx.Bytes()...)
}

func (c *recordConn) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.rx.Bytes()...)
}

// sshPlainPackets walks the plaintext SSH packets of one direction, starting
// after the identification line. It stops at the first length that cannot be a
// plaintext packet, which is where the encrypted phase begins.
func sshPlainPackets(b []byte, max int) [][]byte {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return nil
	}
	b = b[i+1:]
	var out [][]byte
	for len(b) >= 4 && len(out) < max {
		n := binary.BigEndian.Uint32(b[0:4])
		if n < 2 || uint64(n)+4 > uint64(len(b)) {
			break
		}
		body := b[4 : 4+n]
		pad := int(body[0])
		if pad+1 > int(n) {
			break
		}
		out = append(out, body[1:int(n)-pad])
		b = b[4+n:]
	}
	return out
}

// sshServeOnce runs the server half of a camouflage session and hands the
// established transport back.
func sshServeOnce(conn net.Conn, secret []byte) (*SSHTransport, error) {
	tr, err := SSHServerHandshake(conn, SSHHostKey(secret))
	if err != nil {
		return nil, err
	}
	token, err := SSHServerReadAuth(tr)
	if err != nil {
		return nil, err
	}
	if !VerifySSHAuthToken(token, secret, tr.SessionID(), SSHAuthClientToServer) {
		SSHServerRejectAuth(tr)
		return nil, errors.New("ssh: auth rejected")
	}
	if err := SSHServerAcceptAuth(tr, secret); err != nil {
		return nil, err
	}
	return tr, nil
}

type sshSession struct {
	client *SSHTransport
	server *SSHTransport
	rec    *recordConn
}

// sshDial brings up a full client/server session over an in-memory pipe.
func sshDial(t *testing.T, secret []byte) *sshSession {
	t.Helper()
	cliRaw, srvRaw := sshPipe(t)
	t.Cleanup(func() { cliRaw.Close(); srvRaw.Close() })

	rec := &recordConn{Conn: cliRaw}

	type res struct {
		tr  *SSHTransport
		err error
	}
	done := make(chan res, 1)
	go func() {
		tr, err := sshServeOnce(srvRaw, secret)
		done <- res{tr, err}
	}()

	_ = rec.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	client, err := performSSHClientHandshake(rec, secret)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	_ = rec.SetDeadline(time.Time{})
	_ = srvRaw.SetDeadline(time.Time{})
	return &sshSession{client: client, server: r.tr, rec: rec}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// TestSSHHandshakeEndToEnd checks that a real key exchange happens: both ends
// agree on the same exchange hash and the encrypted channel carries data.
func TestSSHHandshakeEndToEnd(t *testing.T) {
	s := sshDial(t, []byte(sshTestSecret))

	if !bytes.Equal(s.client.SessionID(), s.server.SessionID()) {
		t.Fatal("the two ends derived different session identifiers")
	}
	if len(s.client.SessionID()) != 32 {
		t.Fatalf("session id is %d bytes, want 32", len(s.client.SessionID()))
	}

	cli := NewSSHCamouflageConn(s.client)
	srv := NewSSHCamouflageConn(s.server)

	payload := []byte("hello through the encrypted channel")
	go func() { _, _ = cli.Write(payload) }()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(srv, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("server got %q, want %q", buf, payload)
	}

	go func() { _, _ = srv.Write(payload) }()
	buf2 := make([]byte, len(payload))
	if _, err := io.ReadFull(cli, buf2); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf2, payload) {
		t.Fatalf("client got %q, want %q", buf2, payload)
	}
}

// TestSSHLargeWriteRoundTrip pushes more than one channel packet through so the
// chunking path is covered.
func TestSSHLargeWriteRoundTrip(t *testing.T) {
	s := sshDial(t, []byte(sshTestSecret))
	cli := NewSSHCamouflageConn(s.client)
	srv := NewSSHCamouflageConn(s.server)

	payload := make([]byte, 3*sshChannelMaxPacket+1234)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	go func() { _, _ = cli.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the large payload did not survive the round trip")
	}
}

// TestSSHEphemeralKeysAreFreshAndDistinct is the check that the key exchange is
// a key exchange. On the old code both messages carried the same HMAC token, so
// KEX_ECDH_INIT and KEX_ECDH_REPLY held identical bytes and those bytes repeated
// across every connection in a five minute window.
func TestSSHEphemeralKeysAreFreshAndDistinct(t *testing.T) {
	secret := []byte(sshTestSecret)

	grab := func() (qc, qs, cookieC, cookieS []byte) {
		s := sshDial(t, secret)
		sentPkts := sshPlainPackets(s.rec.sent(), 3)
		recvPkts := sshPlainPackets(s.rec.received(), 3)
		if len(sentPkts) < 2 || len(recvPkts) < 2 {
			t.Fatalf("could not read the handshake off the wire (sent %d, received %d packets)",
				len(sentPkts), len(recvPkts))
		}
		var err error
		if qc, err = parseSSHKexECDHInit(sentPkts[1]); err != nil {
			t.Fatalf("parsing KEX_ECDH_INIT off the wire: %v", err)
		}
		if _, qs, _, err = parseSSHKexECDHReply(recvPkts[1]); err != nil {
			t.Fatalf("parsing KEX_ECDH_REPLY off the wire: %v", err)
		}
		if sentPkts[0][0] != sshMsgKexInit || recvPkts[0][0] != sshMsgKexInit {
			t.Fatal("the first packet in each direction is not a KEXINIT")
		}
		return qc, qs, append([]byte(nil), sentPkts[0][1:17]...), append([]byte(nil), recvPkts[0][1:17]...)
	}

	qc1, qs1, cookieC1, cookieS1 := grab()
	qc2, qs2, cookieC2, cookieS2 := grab()

	if bytes.Equal(qc1, qs1) {
		t.Error("KEX_ECDH_INIT and KEX_ECDH_REPLY carry the same public value; a real X25519 exchange never does")
	}
	if bytes.Equal(qc1, qc2) {
		t.Error("two connections with the same secret sent the same client public value")
	}
	if bytes.Equal(qs1, qs2) {
		t.Error("two connections with the same secret sent the same server public value")
	}
	if bytes.Equal(cookieC1, cookieC2) {
		t.Error("the client KEXINIT cookie repeats across connections")
	}
	if bytes.Equal(cookieS1, cookieS2) {
		t.Error("the server KEXINIT cookie repeats across connections")
	}
}

// TestSSHNoUserPayloadOnTheWire is the plaintext check. The old framing copied
// the caller's bytes straight into the SSH packet, so a DPI box reading the
// stream saw IP headers inside what it was told were SSH packets.
func TestSSHNoUserPayloadOnTheWire(t *testing.T) {
	s := sshDial(t, []byte(sshTestSecret))
	cli := NewSSHCamouflageConn(s.client)
	srv := NewSSHCamouflageConn(s.server)

	// A marker plus a synthetic IPv4 header, which is what TUN mode actually
	// hands to the strategy.
	marker := []byte("PAYLOAD-MUST-NOT-APPEAR-IN-CLEAR")
	ipHeader := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06}
	out := append(append([]byte(nil), ipHeader...), marker...)

	go func() { _, _ = cli.Write(out) }()
	got := make([]byte, len(out))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read: %v", err)
	}

	wire := s.rec.wire()
	if bytes.Contains(wire, marker) {
		t.Error("the user payload appears verbatim in the connection bytes")
	}
	if bytes.Contains(wire, out) {
		t.Error("the IP header and payload appear verbatim in the connection bytes")
	}
	// Positive control for the search itself: the same needle is findable in a
	// buffer that does contain it, so a clean result above means absence and
	// not a broken haystack.
	if !bytes.Contains(append(append([]byte(nil), wire...), marker...), marker) {
		t.Fatal("the search cannot find the marker even when it is present")
	}
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// TestSSHTokenReflectionRejected puts a man in the middle that knows no secret
// and simply echoes the client's own token back as the server's answer. On the
// old code this passed, because both directions derived the same value.
func TestSSHTokenReflectionRejected(t *testing.T) {
	secret := []byte(sshTestSecret)
	cliRaw, srvRaw := sshPipe(t)
	defer cliRaw.Close()
	defer srvRaw.Close()

	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	go func() {
		// The attacker can run the transport handshake: it needs no secret.
		tr, err := SSHServerHandshake(srvRaw, SSHHostKey(nil))
		if err != nil {
			return
		}
		token, err := SSHServerReadAuth(tr)
		if err != nil {
			return
		}
		// Reflect the client's own token back at it.
		_ = tr.WritePacket(buildSSHUserAuthBanner(token))
		_ = tr.WritePacket([]byte{sshMsgUserAuthSuccess})
	}()

	if _, err := performSSHClientHandshake(cliRaw, secret); err == nil {
		t.Fatal("the client accepted its own token reflected back as the server's proof")
	}
}

// TestSSHCapturedTokenNotReplayable replays a token lifted off one session into
// a second one. The token is bound to the exchange hash, which covers both
// KEXINIT cookies and both ephemeral keys, so it cannot travel between sessions.
func TestSSHCapturedTokenNotReplayable(t *testing.T) {
	secret := []byte(sshTestSecret)

	first := sshDial(t, secret)
	stolen := SSHAuthToken(secret, first.client.SessionID(), SSHAuthClientToServer)

	// A fresh session; the attacker knows the stolen token but not the secret.
	cliRaw, srvRaw := sshPipe(t)
	defer cliRaw.Close()
	defer srvRaw.Close()
	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		_, err := sshServeOnce(srvRaw, secret)
		errCh <- err
	}()

	tr, err := SSHClientHandshake(cliRaw)
	if err != nil {
		t.Fatalf("attacker transport handshake: %v", err)
	}
	if bytes.Equal(tr.SessionID(), first.client.SessionID()) {
		t.Fatal("two sessions produced the same session id; the replay test proves nothing")
	}
	if err := tr.WritePacket(buildSSHServiceRequest()); err != nil {
		t.Fatalf("service request: %v", err)
	}
	if _, err := tr.ReadPacket(); err != nil {
		t.Fatalf("service accept: %v", err)
	}
	if err := tr.WritePacket(buildSSHUserAuthRequest(stolen)); err != nil {
		t.Fatalf("userauth request: %v", err)
	}
	// Drain the rejection so the server is not left blocked writing it.
	go func() {
		for {
			if _, err := tr.ReadPacket(); err != nil {
				return
			}
		}
	}()

	if err := <-errCh; err == nil {
		t.Fatal("the server accepted a token captured from another session")
	}
}

// TestSSHAuthTokenBindsToDirectionAndSession pins the two properties the token
// derivation has to carry, one broken input at a time.
func TestSSHAuthTokenBindsToDirectionAndSession(t *testing.T) {
	secret := []byte(sshTestSecret)
	sessionA := bytes.Repeat([]byte{0xA1}, 32)
	sessionB := bytes.Repeat([]byte{0xB2}, 32)

	c2s := SSHAuthToken(secret, sessionA, SSHAuthClientToServer)
	s2c := SSHAuthToken(secret, sessionA, SSHAuthServerToClient)

	if bytes.Equal(c2s, s2c) {
		t.Fatal("the two directions derive the same token; reflecting one back would verify")
	}
	if !VerifySSHAuthToken(c2s, secret, sessionA, SSHAuthClientToServer) {
		t.Error("a freshly derived token does not verify")
	}
	if VerifySSHAuthToken(c2s, secret, sessionA, SSHAuthServerToClient) {
		t.Error("a client token verifies as a server token")
	}
	if VerifySSHAuthToken(c2s, secret, sessionB, SSHAuthClientToServer) {
		t.Error("a token verifies against a different session id")
	}
	if VerifySSHAuthToken(c2s, []byte("some-other-secret-entirely!!!!!!"), sessionA, SSHAuthClientToServer) {
		t.Error("a token verifies under the wrong secret")
	}
	if VerifySSHAuthToken(c2s[:16], secret, sessionA, SSHAuthClientToServer) {
		t.Error("a truncated token verifies")
	}
}

// TestSSHWrongSecretRejected drives a full client against a server holding a
// different secret.
func TestSSHWrongSecretRejected(t *testing.T) {
	cliRaw, srvRaw := sshPipe(t)
	defer cliRaw.Close()
	defer srvRaw.Close()
	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		_, err := sshServeOnce(srvRaw, []byte("the-server-secret-is-different!!"))
		errCh <- err
	}()

	if _, err := performSSHClientHandshake(cliRaw, []byte(sshTestSecret)); err == nil {
		t.Fatal("the client completed a handshake against a server with another secret")
	}
	// The client is gone; without this the server blocks writing the rest of
	// its rejection until the deadline.
	cliRaw.Close()
	if err := <-errCh; err == nil {
		t.Fatal("the server authenticated a client with another secret")
	}
}

// TestSSHForgedSignatureRejected serves a KEX_ECDH_REPLY that is well formed in
// every way except the signature, and follows it with NEWKEYS. The client has
// to stop on the signature; if it only stopped because the peer went away, the
// test would pass with the check removed.
func TestSSHForgedSignatureRejected(t *testing.T) {
	cliRaw, srvRaw := sshPipe(t)
	defer cliRaw.Close()
	defer srvRaw.Close()
	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	go func() {
		br := newSSHTestReader(srvRaw)
		if _, err := readSSHBanner(br); err != nil {
			return
		}
		var flight bytes.Buffer
		flight.WriteString(SSHBanner)
		if err := WriteSSHPacket(&flight, BuildSSHServerKexInit()); err != nil {
			return
		}
		if _, err := srvRaw.Write(flight.Bytes()); err != nil {
			return
		}
		if _, err := ReadSSHPacket(br); err != nil {
			return
		}
		initPayload, err := ReadSSHPacket(br)
		if err != nil {
			return
		}
		if _, err := parseSSHKexECDHInit(initPayload); err != nil {
			return
		}
		// A real ephemeral key so the client's X25519 succeeds, a real host key
		// blob so the parse succeeds, and a signature over nothing.
		priv := make([]byte, curve25519.ScalarSize)
		if _, err := rand.Read(priv); err != nil {
			return
		}
		qs, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			return
		}
		host := SSHHostKey([]byte("an-attacker-host-key-seed-value!"))
		ks := sshHostKeyBlob(host.Public().(ed25519.PublicKey))
		badSig := make([]byte, ed25519.SignatureSize)

		var second bytes.Buffer
		_ = WriteSSHPacket(&second, buildSSHKexECDHReply(ks, qs, sshSignatureBlob(badSig)))
		_ = WriteSSHPacket(&second, []byte{sshMsgNewKeys})
		_, _ = srvRaw.Write(second.Bytes())
		// Stay put: the client must refuse on its own, not because we hung up.
		buf := make([]byte, 1)
		_, _ = srvRaw.Read(buf)
	}()

	_, err := SSHClientHandshake(cliRaw)
	if err == nil {
		t.Fatal("the client accepted a KEX_ECDH_REPLY with a signature that does not verify")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("the client stopped for the wrong reason: %v", err)
	}
}

// sshUserAuthNone is the login an ordinary ssh client opens with: method
// "none", carrying no credential at all.
func sshUserAuthNone() []byte {
	out := []byte{sshMsgUserAuthRequest}
	out = sshAppendString(out, []byte("root"))
	out = sshAppendString(out, []byte("ssh-connection"))
	return sshAppendString(out, []byte("none"))
}

// sshOpenUserAuth brings up a transport and gets as far as SERVICE_ACCEPT.
func sshOpenUserAuth(t *testing.T, secret []byte) (*SSHTransport, <-chan error) {
	t.Helper()
	cliRaw, srvRaw := sshPipe(t)
	t.Cleanup(func() { cliRaw.Close(); srvRaw.Close() })
	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	done := make(chan error, 1)
	go func() {
		_, err := sshServeOnce(srvRaw, secret)
		done <- err
	}()

	tr, err := SSHClientHandshake(cliRaw)
	if err != nil {
		t.Fatalf("transport handshake: %v", err)
	}
	if err := tr.WritePacket(buildSSHServiceRequest()); err != nil {
		t.Fatalf("service request: %v", err)
	}
	accept, err := ReadSSHTransportPacket(tr)
	if err != nil {
		t.Fatalf("service accept: %v", err)
	}
	if err := checkSSHServiceMessage(accept, sshMsgServiceAccept); err != nil {
		t.Fatalf("service accept: %v", err)
	}
	return tr, done
}

// TestSSHServerAnswersUnknownLoginLikeSSHD checks the anti-probe behaviour that
// matters most: an ordinary ssh client opens with method "none", which carries
// no token, and a server that hung up on it would stand out from every real SSH
// host. It has to answer USERAUTH_FAILURE and keep going.
func TestSSHServerAnswersUnknownLoginLikeSSHD(t *testing.T) {
	secret := []byte(sshTestSecret)
	tr, done := sshOpenUserAuth(t, secret)

	if err := tr.WritePacket(sshUserAuthNone()); err != nil {
		t.Fatalf("userauth none: %v", err)
	}
	reply, err := ReadSSHTransportPacket(tr)
	if err != nil {
		t.Fatalf("the server hung up on a method-none login instead of refusing it: %v", err)
	}
	if reply[0] != sshMsgUserAuthFailure {
		t.Fatalf("the server answered method none with message %d, want USERAUTH_FAILURE (%d)",
			reply[0], sshMsgUserAuthFailure)
	}

	// The real credential still works on the same connection, which is what a
	// second attempt against a real server looks like.
	token := SSHAuthToken(secret, tr.SessionID(), SSHAuthClientToServer)
	if err := tr.WritePacket(buildSSHUserAuthRequest(token)); err != nil {
		t.Fatalf("userauth password: %v", err)
	}
	banner, err := ReadSSHTransportPacket(tr)
	if err != nil {
		t.Fatalf("userauth reply: %v", err)
	}
	serverToken, err := parseSSHUserAuthBanner(banner)
	if err != nil {
		t.Fatalf("parsing the answering token: %v", err)
	}
	if !VerifySSHAuthToken(serverToken, secret, tr.SessionID(), SSHAuthServerToClient) {
		t.Error("the answering token does not verify")
	}
	if err := <-done; err != nil {
		t.Fatalf("the server did not accept the retry: %v", err)
	}
}

// TestSSHServerBoundsAuthAttempts pins the other half: the retries are finite,
// so a peer cannot sit in the userauth loop forever.
func TestSSHServerBoundsAuthAttempts(t *testing.T) {
	tr, done := sshOpenUserAuth(t, []byte(sshTestSecret))

	for i := 0; i < sshMaxAuthTries; i++ {
		if err := tr.WritePacket(sshUserAuthNone()); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		reply, err := ReadSSHTransportPacket(tr)
		if err != nil {
			t.Fatalf("attempt %d: the server stopped answering early: %v", i, err)
		}
		if reply[0] != sshMsgUserAuthFailure {
			t.Fatalf("attempt %d answered with message %d, want USERAUTH_FAILURE", i, reply[0])
		}
	}

	err := <-done
	if err == nil {
		t.Fatal("the server kept the session after the attempt limit")
	}
	if !errors.Is(err, errSSHAuthRejected) {
		t.Errorf("the server stopped for the wrong reason: %v", err)
	}
}

// TestSSHServerSendsExtInfo checks we answer ext-info-c the way a stock sshd
// does. Advertising the extension and then not sending it is the same class of
// mismatch as offering a kex we cannot run.
func TestSSHServerSendsExtInfo(t *testing.T) {
	cliRaw, srvRaw := sshPipe(t)
	t.Cleanup(func() { cliRaw.Close(); srvRaw.Close() })
	_ = cliRaw.SetDeadline(time.Now().Add(20 * time.Second))
	_ = srvRaw.SetDeadline(time.Now().Add(20 * time.Second))

	go func() { _, _ = sshServeOnce(srvRaw, []byte(sshTestSecret)) }()

	tr, err := SSHClientHandshake(cliRaw)
	if err != nil {
		t.Fatalf("transport handshake: %v", err)
	}
	// Deliberately the raw read, not the skipping one: EXT_INFO has to be the
	// very first packet after NEWKEYS, where a real sshd puts it.
	first, err := tr.ReadPacket()
	if err != nil {
		t.Fatalf("reading the first encrypted packet: %v", err)
	}
	if first[0] != sshMsgExtInfo {
		t.Fatalf("the first packet after NEWKEYS is message %d, want EXT_INFO (%d)", first[0], sshMsgExtInfo)
	}
	if !bytes.Contains(first, []byte("server-sig-algs")) {
		t.Error("EXT_INFO does not carry server-sig-algs")
	}
	if bytes.Contains(first, []byte("ping@openssh.com")) {
		t.Error("EXT_INFO advertises ping@openssh.com, which we do not implement")
	}
}

// ---------------------------------------------------------------------------
// Mimicry
// ---------------------------------------------------------------------------

// These are the exact name-lists that OpenSSH_9.6p1 Ubuntu-3ubuntu13.18 puts on
// the wire, captured from the stock client and the stock sshd on 2026-09-20.
// The banner claims that release, so these lists have to match it: a banner and
// a KEXINIT that disagree are a fingerprint on their own.
var realOpenSSH96ClientLists = []string{
	"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
	"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256",
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
	"none,zlib@openssh.com,zlib",
	"none,zlib@openssh.com,zlib",
	"",
	"",
}

// realOpenSSH96ClientPayloadLen is the measured KEXINIT payload size of the
// stock client; ours has to come out byte for byte the same length.
const realOpenSSH96ClientPayloadLen = 1524

func sshKexInitLists(t *testing.T, payload []byte) []string {
	t.Helper()
	if len(payload) < 17 || payload[0] != sshMsgKexInit {
		t.Fatalf("not a KEXINIT payload (len %d)", len(payload))
	}
	rest := payload[17:]
	out := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		val, r, err := sshReadString(rest)
		if err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
		out = append(out, string(val))
		rest = r
	}
	if len(rest) != 5 {
		t.Errorf("%d bytes after the name-lists, want 5 (first_kex_packet_follows + reserved)", len(rest))
	}
	if rest[0] != 0 {
		t.Errorf("first_kex_packet_follows = %d, want 0", rest[0])
	}
	if !bytes.Equal(rest[1:5], []byte{0, 0, 0, 0}) {
		t.Errorf("reserved = %x, want 00000000", rest[1:5])
	}
	return out
}

// TestSSHClientKexInitMatchesOpenSSH96 compares our client KEXINIT with the one
// captured from the real OpenSSH 9.6p1 named in our banner, list by list.
func TestSSHClientKexInitMatchesOpenSSH96(t *testing.T) {
	payload := BuildSSHClientKexInit()
	if len(payload) != realOpenSSH96ClientPayloadLen {
		t.Errorf("client KEXINIT payload is %d bytes, the real one is %d",
			len(payload), realOpenSSH96ClientPayloadLen)
	}
	names := []string{"kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c"}
	got := sshKexInitLists(t, payload)
	for i := range realOpenSSH96ClientLists {
		if got[i] != realOpenSSH96ClientLists[i] {
			t.Errorf("%s list differs from real OpenSSH 9.6p1:\n got  %q\n want %q", names[i], got[i], realOpenSSH96ClientLists[i])
		}
	}
}

// TestSSHServerKexInitNegotiatesWhatWeSend checks the server lists against the
// two things an observer can derive from them: the algorithm the negotiation
// rules select, and the message sizes that algorithm implies.
func TestSSHServerKexInitNegotiatesWhatWeSend(t *testing.T) {
	got := sshKexInitLists(t, BuildSSHServerKexInit())
	client := sshKexInitLists(t, BuildSSHClientKexInit())

	// RFC 4253 §7.1: the chosen algorithm is the first on the client's list
	// that also appears on the server's.
	pick := func(c, s string) string {
		for _, name := range splitSSHNames(c) {
			if sshNameListHas([]byte(s), name) {
				return name
			}
		}
		return ""
	}
	if a := pick(client[0], got[0]); a != "curve25519-sha256" {
		t.Errorf("kex negotiation selects %q, but we implement curve25519-sha256", a)
	}
	if a := pick(client[1], got[1]); a != "ssh-ed25519" {
		t.Errorf("host key negotiation selects %q, but we sign with ssh-ed25519", a)
	}
	if a := pick(client[2], got[2]); a != "chacha20-poly1305@openssh.com" {
		t.Errorf("cipher negotiation selects %q, but we encrypt with chacha20-poly1305@openssh.com", a)
	}
	if a := pick(client[6], got[6]); a != "none" {
		t.Errorf("compression negotiation selects %q, but we do not compress", a)
	}
	// The ciphers and MACs are the stock sshd lists.
	if got[2] != realOpenSSH96ClientLists[2] || got[4] != realOpenSSH96ClientLists[4] {
		t.Error("the server cipher or MAC lists drifted from the real ones")
	}

	// Picking the right algorithm against our own client is not enough: a
	// prober can pin HostKeyAlgorithms to anything on the list and expect a
	// signature back. Every name we advertise has to be one we can sign with,
	// and ssh-ed25519 is the only one.
	for _, name := range splitSSHNames(got[1]) {
		if name != "ssh-ed25519" {
			t.Errorf("the server advertises host key algorithm %q, which it cannot sign with", name)
		}
	}
}

func splitSSHNames(list string) []string {
	if list == "" {
		return nil
	}
	out := []string{}
	start := 0
	for i := 0; i <= len(list); i++ {
		if i == len(list) || list[i] == ',' {
			out = append(out, list[start:i])
			start = i + 1
		}
	}
	return out
}

// TestSSHPlaintextPacketGeometryMatchesOpenSSH pins the framing of the packets
// that travel in clear. The measured real client KEXINIT is packet_length 1532
// on a 1536 byte wire with seven padding bytes, and those padding bytes are all
// zero: OpenSSH only randomises padding once a cipher is in place.
func TestSSHPlaintextPacketGeometryMatchesOpenSSH(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSSHPacket(&buf, BuildSSHClientKexInit()); err != nil {
		t.Fatalf("WriteSSHPacket: %v", err)
	}
	w := buf.Bytes()
	if len(w) != 1536 {
		t.Errorf("client KEXINIT is %d bytes on the wire, the real one is 1536", len(w))
	}
	packetLen := binary.BigEndian.Uint32(w[0:4])
	if packetLen != 1532 {
		t.Errorf("packet_length = %d, the real one is 1532", packetLen)
	}
	if len(w)%8 != 0 {
		t.Errorf("the wire length %d is not a multiple of the 8 byte block size", len(w))
	}
	padLen := int(w[4])
	if padLen != 7 {
		t.Errorf("padding_length = %d, the real one is 7", padLen)
	}
	pad := w[4+int(packetLen)-padLen : 4+int(packetLen)]
	if !bytes.Equal(pad, make([]byte, padLen)) {
		t.Errorf("plaintext padding is %x, OpenSSH pads plaintext packets with zeros", pad)
	}
}

// TestSSHEncryptedPacketPaddingIsRandom is the other half of the same rule:
// once a cipher is in place OpenSSH fills padding from the CSPRNG, so an
// all-zero tail after NEWKEYS would be its own signature. It drives the real
// WritePacket and reads the padding back out of the sealed packet, because
// exercising the framing helper on its own would not notice WritePacket asking
// for the wrong kind of padding.
func TestSSHEncryptedPacketPaddingIsRandom(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, sshCipherKeyLen)
	c, err := newSSHChaChaCipher(key)
	if err != nil {
		t.Fatalf("newSSHChaChaCipher: %v", err)
	}

	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		sink := &bufConn{}
		tr := &SSHTransport{conn: sink, out: c}
		if err := tr.WritePacket([]byte{sshMsgUserAuthSuccess}); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
		wire := sink.buf.Bytes()
		n, err := c.decryptLength(0, wire[0:4])
		if err != nil {
			t.Fatalf("decryptLength: %v", err)
		}
		plain, err := c.open(0, wire[0:4], wire[4:4+n], wire[4+n:])
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		padLen := int(plain[0])
		pad := plain[len(plain)-padLen:]
		if bytes.Equal(pad, make([]byte, len(pad))) {
			t.Fatal("WritePacket padded an encrypted packet with zeros")
		}
		seen[string(pad)] = true
	}
	if len(seen) < 16 {
		t.Errorf("only %d distinct padding values in 16 packets", len(seen))
	}
}

// TestSSHHandshakePaddingIsZeroOnTheWire checks every plaintext packet a real
// session actually emits, in both directions. The handshake builds some of its
// packets without going through WriteSSHPacket, so pinning that one function
// would leave those call sites unchecked.
func TestSSHHandshakePaddingIsZeroOnTheWire(t *testing.T) {
	s := sshDial(t, []byte(sshTestSecret))

	check := func(dir string, b []byte) int {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			t.Fatalf("%s: no identification line", dir)
		}
		b = b[i+1:]
		n := 0
		for len(b) >= 4 && n < 3 {
			length := binary.BigEndian.Uint32(b[0:4])
			if length < 2 || uint64(length)+4 > uint64(len(b)) {
				break
			}
			body := b[4 : 4+length]
			padLen := int(body[0])
			if padLen+1 > int(length) {
				break
			}
			pad := body[int(length)-padLen:]
			if !bytes.Equal(pad, make([]byte, padLen)) {
				t.Errorf("%s packet %d padded with %x; OpenSSH pads plaintext packets with zeros", dir, n, pad)
			}
			if (4+int(length))%8 != 0 {
				t.Errorf("%s packet %d is %d bytes on the wire, not a multiple of 8", dir, n, 4+length)
			}
			b = b[4+length:]
			n++
		}
		return n
	}
	if got := check("client->server", s.rec.sent()); got != 3 {
		t.Errorf("read %d plaintext packets from the client, want 3 (KEXINIT, KEX_ECDH_INIT, NEWKEYS)", got)
	}
	if got := check("server->client", s.rec.received()); got != 3 {
		t.Errorf("read %d plaintext packets from the server, want 3 (KEXINIT, KEX_ECDH_REPLY, NEWKEYS)", got)
	}
}

// TestSSHBannerAgreesWithKexInit is the consistency check between the two
// things an observer reads first.
func TestSSHBannerAgreesWithKexInit(t *testing.T) {
	const want = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18\r\n"
	if SSHBanner != want {
		t.Errorf("banner is %q; the pinned KEXINIT lists were captured from %q", SSHBanner, want)
	}
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

// TestSSHPlaintextPacketLengthCap makes sure a forged length is refused before
// anything is allocated for it. The body is supplied in full, so a reader
// without the bound would hand the packet back happily: running out of input is
// not what makes this fail.
func TestSSHPlaintextPacketLengthCap(t *testing.T) {
	framed := func(length int) *bytes.Buffer {
		body := make([]byte, length)
		body[0] = 4 // padding_length, so the rest of the parse is well formed
		var buf bytes.Buffer
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(length))
		buf.Write(hdr[:])
		buf.Write(body)
		return &buf
	}

	if _, err := ReadSSHPacket(framed(sshMaxHandshakePacket + 8)); err == nil {
		t.Error("a complete packet one block over the cap was accepted")
	}
	// Positive control through the same path: right under the cap it reads.
	if _, err := ReadSSHPacket(framed(sshMaxHandshakePacket)); err != nil {
		t.Errorf("a packet at the cap was refused: %v", err)
	}
	// A length that claims more than anyone will ever send must not turn into
	// an allocation either.
	var huge bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	huge.Write(hdr[:])
	huge.Write(bytes.Repeat([]byte{0xAA}, 64))
	if _, err := ReadSSHPacket(&huge); err == nil {
		t.Error("packet_length 0xFFFFFFFF was accepted")
	}
}

// TestSSHEncryptedPacketLengthCap does the same for the encrypted path, where
// the length is decrypted before it can be authenticated and therefore has to
// be bounded on its own. Each packet below is sealed for real and delivered in
// full, so without the bound ReadPacket would return it.
func TestSSHEncryptedPacketLengthCap(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, sshCipherKeyLen)
	c, err := newSSHChaChaCipher(key)
	if err != nil {
		t.Fatalf("newSSHChaChaCipher: %v", err)
	}

	read := func(packetLen int) error {
		packet := make([]byte, packetLen)
		packet[0] = 4 // padding_length
		wire, err := c.seal(0, packet)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		tr := &SSHTransport{br: bufio.NewReader(bytes.NewReader(wire)), in: c}
		_, err = tr.ReadPacket()
		return err
	}

	if err := read(sshMaxPacket + 8); err == nil {
		t.Error("an encrypted packet one block over the cap was accepted")
	}
	if err := read(13); err == nil {
		t.Error("an encrypted packet_length that is not a multiple of the block size was accepted")
	}
	// Positive control through the same path.
	if err := read(64); err != nil {
		t.Errorf("a well-formed encrypted packet was refused: %v", err)
	}
}

// TestSSHBannerCap stops a peer from growing our heap with an endless
// identification line. The long line below is properly terminated, so hitting
// the end of the input is not what makes this fail.
func TestSSHBannerCap(t *testing.T) {
	long := append(bytes.Repeat([]byte{'x'}, 64*1024), '\n')
	if _, err := readSSHBanner(newSSHTestReader(bytes.NewReader(long))); err == nil {
		t.Error("a banner far longer than the cap was accepted")
	}
	if _, err := readSSHBanner(newSSHTestReader(bytes.NewReader([]byte{'x', 'y'}))); err == nil {
		t.Error("a line with no terminator at all was accepted")
	}
	// Positive control: a real identification line still reads through the
	// same function.
	got, err := readSSHBanner(newSSHTestReader(bytes.NewReader([]byte(SSHBanner))))
	if err != nil {
		t.Fatalf("a real banner was refused: %v", err)
	}
	if sshTrimBanner(got) != sshTrimBanner(SSHBanner) {
		t.Errorf("readSSHBanner returned %q, want %q", got, sshTrimBanner(SSHBanner))
	}
}

// TestSSHAuthFieldLengthChecked refuses an oversized auth field before it is
// decoded.
func TestSSHAuthFieldLengthChecked(t *testing.T) {
	huge := bytes.Repeat([]byte("ab"), 64*1024)
	if _, err := sshDecodeToken(huge); err == nil {
		t.Error("an oversized auth field was decoded")
	}
	if _, err := sshDecodeToken([]byte("not-hex-at-all")); err == nil {
		t.Error("a short auth field was decoded")
	}
	good := make([]byte, hex.EncodedLen(sshAuthLen))
	hex.Encode(good, bytes.Repeat([]byte{0x11}, sshAuthLen))
	if _, err := sshDecodeToken(good); err != nil {
		t.Errorf("a well-formed auth field was refused: %v", err)
	}
}

// TestSSHStringBoundsChecked pins the parser against forged lengths.
func TestSSHStringBoundsChecked(t *testing.T) {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 0xFFFFFFF0)
	if _, _, err := sshReadString(hdr[:]); err == nil {
		t.Error("a string length past the end of the buffer was accepted")
	}
	if _, _, err := sshReadString([]byte{0, 0}); err == nil {
		t.Error("a truncated string header was accepted")
	}
}

// ---------------------------------------------------------------------------
// Cipher
// ---------------------------------------------------------------------------

// TestSSHChaChaSealOpenRoundTrip covers the OpenSSH chacha20-poly1305
// construction, including that a tampered byte fails authentication and that
// the sequence number is part of the binding.
func TestSSHChaChaSealOpenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x3C}, sshCipherKeyLen)
	c, err := newSSHChaChaCipher(key)
	if err != nil {
		t.Fatalf("newSSHChaChaCipher: %v", err)
	}
	packet, err := sshFramePacket([]byte("the quick brown fox"), 4, true)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := c.seal(3, packet)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	gotLen, err := c.decryptLength(3, wire[0:4])
	if err != nil {
		t.Fatalf("decryptLength: %v", err)
	}
	if int(gotLen) != len(packet) {
		t.Fatalf("decrypted length %d, want %d", gotLen, len(packet))
	}
	plain, err := c.open(3, wire[0:4], wire[4:4+gotLen], wire[4+gotLen:])
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(plain, packet) {
		t.Fatal("the packet did not survive seal/open")
	}
	if _, err := c.open(4, wire[0:4], wire[4:4+gotLen], wire[4+gotLen:]); err == nil {
		t.Error("a packet opened under the wrong sequence number")
	}
	tampered := append([]byte(nil), wire...)
	tampered[6] ^= 0x01
	if _, err := c.open(3, tampered[0:4], tampered[4:4+gotLen], tampered[4+gotLen:]); err == nil {
		t.Error("a tampered packet authenticated")
	}
}

// TestSSHHostKeyIsStablePerSecret checks the host key does not rotate on every
// restart for a configured server, and differs between servers.
func TestSSHHostKeyIsStablePerSecret(t *testing.T) {
	a := SSHHostKey([]byte(sshTestSecret))
	b := SSHHostKey([]byte(sshTestSecret))
	if !bytes.Equal(a, b) {
		t.Error("the host key changes between calls for the same secret")
	}
	c := SSHHostKey([]byte("a-completely-different-secret!!!"))
	if bytes.Equal(a, c) {
		t.Error("two different secrets produce the same host key")
	}
}
