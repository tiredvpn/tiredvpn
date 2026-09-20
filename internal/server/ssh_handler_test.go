package server

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// sshTestPipe returns a connected pair over loopback TCP. net.Pipe is
// synchronous and unbuffered, so it deadlocks on the flights the SSH handshake
// sends without waiting; TCP is what the server actually listens on.
func sshTestPipe(t *testing.T) (client, server net.Conn) {
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

// sshTestSession is one side of an SSH camouflage session brought up against
// sshServerHandshake.
type sshTestSession struct {
	transport *strategy.SSHTransport
	clientID  clientIdentity
	err       error
}

// runSSHServerHandshake starts sshServerHandshake on one end of a pipe and
// hands the other end to the caller.
func runSSHServerHandshake(t *testing.T, srvCtx *serverContext) (net.Conn, <-chan sshTestSession) {
	t.Helper()
	clientConn, serverConn := sshTestPipe(t)
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

	done := make(chan sshTestSession, 1)
	go func() {
		tr, id, err := sshServerHandshake(serverConn, srvCtx, testLogger(t))
		done <- sshTestSession{tr, id, err}
	}()
	return clientConn, done
}

// sshTestClient runs the client half against the server under test.
func sshTestClient(conn net.Conn, secret []byte) (*strategy.SSHTransport, error) {
	tr, err := strategy.SSHClientHandshake(conn)
	if err != nil {
		return nil, err
	}
	if err := strategy.SSHClientAuth(tr, secret); err != nil {
		return nil, err
	}
	return tr, nil
}

// TestVerifySSHAuth mirrors TestVerifyIMAPAuth for the SSH transport. Every
// token is now bound to one session, so the session id is part of the input.
func TestVerifySSHAuth(t *testing.T) {
	global := []byte(camouflageTestSecret)
	perClient := "per-client-secret-also-32-bytes!"
	session := bytes.Repeat([]byte{0x5E}, 32)
	other := bytes.Repeat([]byte{0xA7}, 32)

	srvCtx := newTestServerContext(t)
	srvCtx.cfg.Secret = global
	r := NewClientRegistry(nil)
	r.byID["c1"] = &ClientConfig{ID: "c1", Secret: perClient, Enabled: true}
	srvCtx.registry = r

	tok := func(secret, sess []byte) []byte {
		return strategy.SSHAuthToken(secret, sess, strategy.SSHAuthClientToServer)
	}

	if id, _, ok := verifySSHAuth(tok([]byte(perClient), session), session, srvCtx); !ok || id.id != "c1" || !id.perClient {
		t.Errorf("per-client token: id=%q perClient=%v ok=%v, want c1/true/true", id.id, id.perClient, ok)
	}
	if id, _, ok := verifySSHAuth(tok(global, session), session, srvCtx); !ok || id.id != "global" || id.perClient {
		t.Errorf("global token: id=%q perClient=%v ok=%v, want global/false/true", id.id, id.perClient, ok)
	}
	if _, _, ok := verifySSHAuth(tok([]byte("nope-nope-nope-nope-nope-nope!!"), session), session, srvCtx); ok {
		t.Error("an unknown secret authenticated")
	}
	// A token minted for another session must not open this one; that is what
	// stops a captured token from being replayed.
	if _, _, ok := verifySSHAuth(tok(global, other), session, srvCtx); ok {
		t.Error("a token bound to another session authenticated")
	}
	// The server's own answering token must not work as a client token: the two
	// directions use different contexts, so reflection cannot pass.
	reflected := strategy.SSHAuthToken(global, session, strategy.SSHAuthServerToClient)
	if _, _, ok := verifySSHAuth(reflected, session, srvCtx); ok {
		t.Error("a server-to-client token was accepted as a client token")
	}
	// An IMAP token must not open an SSH session either.
	if _, _, ok := verifySSHAuth(strategy.GenerateIMAPAuthToken(global), session, srvCtx); ok {
		t.Error("an IMAP auth token was accepted by the SSH verifier")
	}
}

// TestSSHServerHandshakeSuccess drives the SSH handshake end to end: banner,
// KEXINIT, the curve25519 exchange, NEWKEYS, and the userauth round trip inside
// the encrypted channel.
func TestSSHServerHandshakeSuccess(t *testing.T) {
	srvCtx := camouflageCtx(t)
	clientConn, done := runSSHServerHandshake(t, srvCtx)

	clientTr, err := sshTestClient(clientConn, []byte(camouflageTestSecret))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("sshServerHandshake: %v", res.err)
		}
		if res.clientID.id != "global" {
			t.Errorf("clientID = %q, want global", res.clientID.id)
		}
		if res.clientID.perClient {
			t.Error("the global secret must not come back marked per-client")
		}
		if !bytes.Equal(res.transport.SessionID(), clientTr.SessionID()) {
			t.Error("the two ends disagree on the session id")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("sshServerHandshake did not return")
	}
}

// TestSSHServerHandshakeRejections covers the failure modes. Everything that
// fails before the encrypted channel is up has to fall through to the fake
// website; a token that fails after it must not, which is what the sentinel
// error distinguishes.
func TestSSHServerHandshakeRejections(t *testing.T) {
	tests := []struct {
		name        string
		script      func(t *testing.T, conn net.Conn)
		postNewKeys bool
	}{
		{
			name:   "client hangs up before the banner",
			script: func(t *testing.T, conn net.Conn) { conn.Close() },
		},
		{
			name: "not an SSH-2.0 banner",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte("SSH-1.5-ancient\r\n"))
			},
		},
		{
			name: "hangs up after the banner",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte(strategy.SSHBanner))
				buf := make([]byte, 4096)
				conn.Read(buf)
				conn.Close()
			},
		},
		{
			name: "KEXINIT offering nothing we implement",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte(strategy.SSHBanner))
				buf := make([]byte, 4096)
				conn.Read(buf)
				// A KEXINIT-shaped payload with empty name-lists.
				payload := make([]byte, 17)
				payload[0] = 20
				for i := 0; i < 10; i++ {
					payload = append(payload, 0, 0, 0, 0)
				}
				payload = append(payload, 0, 0, 0, 0, 0)
				strategy.WriteSSHPacket(conn, payload)
			},
		},
		{
			name: "garbage where KEX_ECDH_INIT belongs",
			script: func(t *testing.T, conn net.Conn) {
				conn.Write([]byte(strategy.SSHBanner))
				buf := make([]byte, 4096)
				conn.Read(buf)
				strategy.WriteSSHPacket(conn, strategy.BuildSSHClientKexInit())
				strategy.WriteSSHPacket(conn, []byte{99, 0, 0, 0, 0})
			},
		},
		{
			name:        "auth token from the wrong secret",
			postNewKeys: true,
			script: func(t *testing.T, conn net.Conn) {
				_, err := sshTestClient(conn, []byte("the-wrong-secret-entirely!!!!!!"))
				if err == nil {
					t.Error("the client completed auth with the wrong secret")
				}
				conn.Close()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvCtx := camouflageCtx(t)
			clientConn, done := runSSHServerHandshake(t, srvCtx)

			tt.script(t, clientConn)
			clientConn.Close()

			select {
			case res := <-done:
				if res.err == nil {
					t.Fatal("handshake succeeded, want a rejection")
				}
				rejected := errors.Is(res.err, strategy.SSHAuthRejectedError())
				if rejected != tt.postNewKeys {
					t.Errorf("errors.Is(err, SSHAuthRejected) = %v, want %v (err: %v)",
						rejected, tt.postNewKeys, res.err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("sshServerHandshake did not return")
			}
		})
	}
}

// TestSSHServerRejectsReflectedToken is the man-in-the-middle case: a peer that
// knows no secret runs the transport handshake and sends back whatever token it
// was given. It must not authenticate.
func TestSSHServerRejectsReflectedToken(t *testing.T) {
	srvCtx := camouflageCtx(t)
	clientConn, done := runSSHServerHandshake(t, srvCtx)

	tr, err := strategy.SSHClientHandshake(clientConn)
	if err != nil {
		t.Fatalf("transport handshake: %v", err)
	}
	// The attacker completes the transport handshake, which needs no secret,
	// and then has nothing better to offer than the session id itself.
	go func() {
		_ = strategy.SSHClientAuth(tr, tr.SessionID())
		for {
			if _, err := tr.ReadPacket(); err != nil {
				return
			}
		}
	}()

	select {
	case res := <-done:
		if res.err == nil {
			t.Fatal("the server authenticated a peer that knows no secret")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("sshServerHandshake did not return")
	}
}
