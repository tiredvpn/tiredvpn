package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// These read the credential a strategy actually put on the socket, then ask
// which secret produced it. That is the question a test on the derivation
// function cannot answer: the derivation is right either way, and what goes
// wrong is the CALL SITE handing it the secret the strategy was constructed
// with instead of the one this dial is for.
//
// Each of these fails on exactly that swap, and each carries its own positive
// control - the same bytes checked against the construction secret must NOT
// verify, or the test would pass against a strategy that ignores the secret
// altogether.
//
// Two secrets, and which is which matters: builtSecret is what the strategy is
// constructed with, dialSecret is the endpoint's. They must never be equal.
const (
	wireBuiltSecret = "the-secret-this-strategy-was-constructed-with"
	wireDialSecret  = "the-secret-of-the-endpoint-being-dialled"
)

// managerAt builds a manager whose single endpoint is addr with the dial
// secret, so Connect resolves that key exactly the way production does.
func managerAt(t *testing.T, addr string) *Manager {
	t.Helper()
	m := NewManager()
	m.setDefaultSecret([]byte(wireBuiltSecret))
	if err := m.SetEndpointsTuned([]endpoint.Endpoint{
		{Name: "peer", V4: addr, Order: 0, Secret: wireDialSecret},
	}, endpoint.Tuning{Family: v4Only()}); err != nil {
		t.Fatalf("SetEndpointsTuned: %v", err)
	}
	return m
}

// acceptOne runs serve on the first connection and hands back whatever it
// returned. The strategy's dial is expected to fail - these servers only get as
// far as the credential - so the caller ignores the dial error.
func acceptOne(t *testing.T, serve func(net.Conn) (any, error)) (addr string, result <-chan any) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	out := make(chan any, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		first := true
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(out)
				return
			}
			if !first {
				// The manager retries a failed strategy, and these servers play
				// their part exactly once. Refusing the retries immediately keeps
				// the test off the dial timeout.
				conn.Close()
				continue
			}
			first = false
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			got, err := serve(conn)
			conn.Close()
			if err != nil {
				t.Errorf("server side: %v", err)
				close(out)
				return
			}
			out <- got
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String(), out
}

func awaitCredential(t *testing.T, ch <-chan any) any {
	t.Helper()
	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("the server never reached the client's credential")
		}
		return got
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the client's credential")
		return nil
	}
}

// TestSSHCamouflageAuthenticatesWithTheDialSecret reads the token the fake SSH
// KEX_ECDH_INIT carries and checks it belongs to the endpoint's secret.
func TestSSHCamouflageAuthenticatesWithTheDialSecret(t *testing.T) {
	addr, tokens := acceptOne(t, func(conn net.Conn) (any, error) {
		br := bufio.NewReader(conn)
		if _, err := br.ReadString('\n'); err != nil { // client banner
			return nil, err
		}
		if _, err := conn.Write([]byte(SSHBanner)); err != nil {
			return nil, err
		}
		if _, err := ReadSSHPacket(br); err != nil { // client KEXINIT
			return nil, err
		}
		if err := WriteSSHPacket(conn, BuildSSHKexInit()); err != nil {
			return nil, err
		}
		payload, err := ReadSSHPacket(br) // ECDH init carrying the token
		if err != nil {
			return nil, err
		}
		return ParseSSHKexPubKey(payload, sshMsgKexECDHInit)
	})

	m := managerAt(t, addr)
	s := NewSSHCamouflageStrategy(m, []byte(wireBuiltSecret))
	m.Register(s)
	dialAndIgnore(t, m, addr)

	token := awaitCredential(t, tokens).([]byte)
	if !VerifySSHAuthToken(token, []byte(wireDialSecret)) {
		t.Fatal("the SSH token does not verify under the endpoint's secret")
	}
	if VerifySSHAuthToken(token, []byte(wireBuiltSecret)) {
		t.Fatal("the SSH token verifies under the construction secret too; this test cannot tell them apart")
	}
}

// imapLogin is what the fake IMAP server pulls out of the LOGIN line.
type imapLogin struct {
	user  string
	token []byte
}

// TestIMAPCamouflageAuthenticatesWithTheDialSecret covers both credentials the
// IMAP camouflage derives: the token in the password field and the username,
// which is the first four bytes of the secret in hex.
func TestIMAPCamouflageAuthenticatesWithTheDialSecret(t *testing.T) {
	addr, logins := acceptOne(t, func(conn net.Conn) (any, error) {
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, err
			}
			switch {
			case strings.HasPrefix(line, "A001 CAPABILITY"):
				if _, err := conn.Write([]byte("* CAPABILITY IMAP4rev1\r\nA001 OK done\r\n")); err != nil {
					return nil, err
				}
			case strings.HasPrefix(line, "A002 LOGIN "):
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) != 4 {
					return nil, io.ErrUnexpectedEOF
				}
				tok, err := base64.StdEncoding.DecodeString(fields[3])
				if err != nil {
					return nil, err
				}
				return imapLogin{user: fields[2], token: tok}, nil
			}
		}
	})

	m := managerAt(t, addr)
	s := NewIMAPCamouflageStrategy(m, []byte(wireBuiltSecret))
	m.Register(s)
	dialAndIgnore(t, m, addr)

	got := awaitCredential(t, logins).(imapLogin)
	if !VerifyIMAPAuthToken(got.token, []byte(wireDialSecret)) {
		t.Fatal("the IMAP token does not verify under the endpoint's secret")
	}
	if VerifyIMAPAuthToken(got.token, []byte(wireBuiltSecret)) {
		t.Fatal("the IMAP token verifies under the construction secret too")
	}
	if want := imapUsername([]byte(wireDialSecret)); got.user != want {
		t.Fatalf("LOGIN user = %q, want %q (derived from the endpoint's secret)", got.user, want)
	}
}

// TestWebSocketPaddedAuthenticatesWithTheDialSecret reads X-Auth-Token off the
// upgrade request, which the strategy sends inside TLS.
func TestWebSocketPaddedAuthenticatesWithTheDialSecret(t *testing.T) {
	addr, tokens := acceptOne(t, func(raw net.Conn) (any, error) {
		conn, err := serverTLS(t, raw)
		if err != nil {
			return nil, err
		}
		if _, err := protocol.ReadDispatch(conn); err != nil {
			return nil, err
		}
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, err
			}
			if v, ok := strings.CutPrefix(line, "X-Auth-Token: "); ok {
				return hex.DecodeString(strings.TrimSpace(v))
			}
			if strings.TrimSpace(line) == "" {
				return nil, io.ErrUnexpectedEOF
			}
		}
	})

	m := managerAt(t, addr)
	s := NewWebSocketPaddedStrategy(m, []byte(wireBuiltSecret))
	m.Register(s)
	dialAndIgnore(t, m, addr)

	assertAuthTokenSecret(t, awaitCredential(t, tokens).([]byte), "WebSocket upgrade")
}

// TestTrafficMorphAuthenticatesWithTheDialSecret reads the 32-byte token out of
// the MRPH handshake.
func TestTrafficMorphAuthenticatesWithTheDialSecret(t *testing.T) {
	addr, tokens := acceptOne(t, func(raw net.Conn) (any, error) {
		conn, err := serverTLS(t, raw)
		if err != nil {
			return nil, err
		}
		if _, err := protocol.ReadDispatch(conn); err != nil {
			return nil, err
		}
		// MRPH(4) + nameLen(1) + name(N) + auth(32) + shaperID(1)
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			return nil, err
		}
		if !bytes.Equal(head[:4], []byte("MRPH")) {
			return nil, io.ErrUnexpectedEOF
		}
		rest := make([]byte, int(head[4])+32+1)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, err
		}
		return rest[int(head[4]) : int(head[4])+32], nil
	})

	m := managerAt(t, addr)
	s := NewTrafficMorphStrategy(m, YandexVideoProfile, nil, []byte(wireBuiltSecret))
	m.Register(s)
	dialAndIgnore(t, m, addr)

	assertAuthTokenSecret(t, awaitCredential(t, tokens).([]byte), "MRPH handshake")
}

// assertAuthTokenSecret checks a generateAuthToken value against both secrets.
//
// The token is bucketed to the minute, so a run that straddles a boundary would
// otherwise flake; neighbouring buckets are accepted, which is what the server
// does too.
func assertAuthTokenSecret(t *testing.T, token []byte, what string) {
	t.Helper()
	if !authTokenMatches(token, []byte(wireDialSecret)) {
		t.Fatalf("the %s token does not verify under the endpoint's secret", what)
	}
	if authTokenMatches(token, []byte(wireBuiltSecret)) {
		t.Fatalf("the %s token verifies under the construction secret too", what)
	}
}

func authTokenMatches(token, secret []byte) bool {
	for _, skew := range []time.Duration{0, -time.Minute, time.Minute} {
		if bytes.Equal(token, authTokenAt(secret, time.Now().Add(skew))) {
			return true
		}
	}
	return false
}

// authTokenAt mirrors generateAuthToken at a chosen time. Spelled out rather
// than calling generateAuthToken, which can only answer for the current minute
// and would otherwise make this test compare a function against itself.
func authTokenAt(secret []byte, at time.Time) []byte {
	bucket := make([]byte, 8)
	binary.BigEndian.PutUint64(bucket, uint64(at.Unix()/60))
	h := hmac.New(sha256.New, secret)
	h.Write(bucket)
	h.Write([]byte("http2-stego-auth"))
	return h.Sum(nil)[:32]
}

// dialAndIgnore runs one Connect against the recording server. It is expected to
// fail: these servers stop at the credential and never complete a handshake.
func dialAndIgnore(t *testing.T, m *Manager, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conn, _, err := m.Connect(ctx, addr)
	if err == nil {
		conn.Close()
		t.Fatal("the recording server completed a handshake it does not implement")
	}
}

// serverTLS wraps raw in a TLS server with a throwaway self-signed certificate.
// Every strategy here dials with InsecureSkipVerify, so the certificate only has
// to exist.
func serverTLS(t *testing.T, raw net.Conn) (net.Conn, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "recorder"},
		DNSNames:     []string{"recorder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	conn := stdtls.Server(raw, &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	return conn, nil
}

// TestSeqovlDecoyMarkerUsesTheDialSecret reads the decoy record seqovl puts in
// front of the ClientHello and recomputes its marker.
//
// The marker is HMAC(secret, salt||nonce) over a nonce chosen per connection, so
// it cannot be compared against a fixed value - the nonce comes off the wire and
// the marker is recomputed under each secret in turn. That is also what the
// server does.
func TestSeqovlDecoyMarkerUsesTheDialSecret(t *testing.T) {
	addr, records := acceptOne(t, func(conn net.Conn) (any, error) {
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			return nil, err
		}
		if head[0] != 0x16 {
			return nil, io.ErrUnexpectedEOF
		}
		body := make([]byte, int(head[3])<<8|int(head[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		return body, nil
	})

	m := managerAt(t, addr)
	s := NewSeqovlStrategy(m, []byte(wireBuiltSecret), false)
	m.Register(s)
	dialAndIgnore(t, m, addr)

	body := awaitCredential(t, records).([]byte)
	if len(body) < seqovlNonceLen+seqovlMarkerLen {
		t.Fatalf("decoy payload is %d bytes, too short to hold a nonce and a marker", len(body))
	}
	nonce := body[:seqovlNonceLen]
	marker := body[seqovlNonceLen : seqovlNonceLen+seqovlMarkerLen]

	if !bytes.Equal(marker, seqovlMarker([]byte(wireDialSecret), nonce)) {
		t.Fatal("the decoy marker was not computed under the endpoint's secret")
	}
	if bytes.Equal(marker, seqovlMarker([]byte(wireBuiltSecret), nonce)) {
		t.Fatal("the decoy marker also matches the construction secret; this test cannot tell them apart")
	}
}

// TestGenevaAuthenticatesWithTheDialSecret is the same shape as the WebSocket
// one - Geneva reuses that upgrade format - but it goes through a different
// strategy, and the call site is a different line.
func TestGenevaAuthenticatesWithTheDialSecret(t *testing.T) {
	addr, tokens := acceptOne(t, func(raw net.Conn) (any, error) {
		conn, err := serverTLS(t, raw)
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, err
			}
			if v, ok := strings.CutPrefix(line, "X-Auth-Token: "); ok {
				return hex.DecodeString(strings.TrimSpace(v))
			}
		}
	})

	m := managerAt(t, addr)
	g := NewGenevaStrategy(m, []byte(wireBuiltSecret), "russia")
	m.Register(g)
	dialAndIgnore(t, m, addr)

	assertAuthTokenSecret(t, awaitCredential(t, tokens).([]byte), "Geneva upgrade")
}
