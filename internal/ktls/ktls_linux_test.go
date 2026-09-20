//go:build linux

package ktls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"hash"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestTLSModuleLoaded(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"present", "nf_tables 12345 0 - Live 0x0\ntls 45056 0 - Live 0x0\n", true},
		{"absent", "nf_tables 12345 0 - Live 0x0\nxfrm_user 40960 1 - Live 0x0\n", false},
		{"empty", "", false},
		{"first line", "tls 45056 0 - Live 0x0\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tlsModuleLoaded([]byte(tc.data)); got != tc.want {
				t.Fatalf("tlsModuleLoaded(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

// independentHkdfLabel builds the TLS 1.3 HkdfLabel structure from scratch using
// binary.Write, deliberately not sharing code with hkdfExpandLabel. It is the
// positive control for the exposition layout: RFC 8446 defines
//
//	struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
//
// with label = "tls13 " + Label.
func independentHkdfLabel(t *testing.T, label string, context []byte, length int) []byte {
	t.Helper()
	full := "tls13 " + label
	if len(full) > 255 || len(context) > 255 || length > 0xffff {
		t.Fatalf("test label out of range")
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint16(length)); err != nil {
		t.Fatal(err)
	}
	buf.WriteByte(byte(len(full)))
	buf.WriteString(full)
	buf.WriteByte(byte(len(context)))
	buf.Write(context)
	return buf.Bytes()
}

func expandControl(t *testing.T, h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	r := hkdf.Expand(h, secret, independentHkdfLabel(t, label, context, length))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHKDFExpandLabel checks hkdfExpandLabel against the independent control for
// several labels, lengths, hashes and a non-empty context. A layout bug (wrong
// length prefix, missing "tls13 " prefix, off-by-one) diverges from the control.
func TestHKDFExpandLabel(t *testing.T) {
	secret := bytes.Repeat([]byte{0xab}, 32)

	cases := []struct {
		h      func() hash.Hash
		label  string
		ctx    []byte
		length int
	}{
		{sha256.New, "key", nil, 16},
		{sha256.New, "iv", nil, 12},
		{sha256.New, "key", nil, 32},
		{sha512.New384, "key", nil, 32},
		{sha512.New384, "iv", nil, 12},
		{sha256.New, "derived", []byte("some-context-bytes"), 32},
	}
	for _, tc := range cases {
		got := hkdfExpandLabel(tc.h, secret, tc.label, tc.ctx, tc.length)
		want := expandControl(t, tc.h, secret, tc.label, tc.ctx, tc.length)
		if len(got) != tc.length {
			t.Fatalf("label=%q len(got)=%d want %d", tc.label, len(got), tc.length)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("label=%q len=%d: hkdfExpandLabel=%x, control=%x", tc.label, tc.length, got, want)
		}
	}
}

func TestDeriveKeys(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5c}, 48)

	cases := []struct {
		cipher  uint16
		h       func() hash.Hash
		keyLen  int
	}{
		{TLS_AES_128_GCM_SHA256, sha256.New, 16},
		{TLS_AES_256_GCM_SHA384, sha512.New384, 32},
		{TLS_CHACHA20_POLY1305_SHA256, sha256.New, 32},
	}
	for _, tc := range cases {
		key, iv, err := deriveKeys(secret, tc.cipher)
		if err != nil {
			t.Fatalf("cipher 0x%04x: deriveKeys error: %v", tc.cipher, err)
		}
		if len(key) != tc.keyLen {
			t.Fatalf("cipher 0x%04x: key len %d, want %d", tc.cipher, len(key), tc.keyLen)
		}
		if len(iv) != 12 {
			t.Fatalf("cipher 0x%04x: iv len %d, want 12", tc.cipher, len(iv))
		}
		// Independent control over the full derivation chain.
		wantKey := expandControl(t, tc.h, secret, "key", nil, tc.keyLen)
		wantIV := expandControl(t, tc.h, secret, "iv", nil, 12)
		if !bytes.Equal(key, wantKey) {
			t.Fatalf("cipher 0x%04x: key=%x, control=%x", tc.cipher, key, wantKey)
		}
		if !bytes.Equal(iv, wantIV) {
			t.Fatalf("cipher 0x%04x: iv=%x, control=%x", tc.cipher, iv, wantIV)
		}
	}
}

func TestDeriveKeysUnsupportedCipher(t *testing.T) {
	if _, _, err := deriveKeys(make([]byte, 32), 0x9999); err == nil {
		t.Fatal("deriveKeys accepted an unsupported cipher suite")
	}
}

func TestSetCryptoInfoUnsupportedCipher(t *testing.T) {
	// Unsupported suites hit the default branch and return before any syscall,
	// so the fd is never touched.
	if err := setCryptoInfo(-1, TLS_TX, 0x9999, nil, nil, [8]byte{}); err == nil {
		t.Fatal("setCryptoInfo accepted an unsupported cipher suite")
	}
}

// --- reflection-based state extraction over a real TLS 1.3 handshake ---

func tls13Pair(t *testing.T, clientMax uint16) (client, server *tls.Conn) {
	t.Helper()

	cert := selfSigned(t)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         clientMax,
	}

	client = tls.Client(c1, clientCfg)
	server = tls.Server(c2, serverCfg)

	errCh := make(chan error, 2)
	go func() { errCh <- server.Handshake() }()
	go func() { errCh <- client.Handshake() }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("handshake timed out")
		}
	}
	return client, server
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ktls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ktls-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestExtractTLSState is the positive control that the reflection into
// crypto/tls internals still matches this Go toolchain (field names vers,
// cipherSuite, in/out, trafficSecret, seq). If crypto/tls renames a field, kTLS
// silently falls back to userspace crypto - this test turns that into a failure.
func TestExtractTLSState(t *testing.T) {
	client, _ := tls13Pair(t, tls.VersionTLS13)
	if client.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("negotiated version 0x%04x, want TLS 1.3", client.ConnectionState().Version)
	}

	state, err := extractTLSState(client)
	if err != nil {
		t.Fatalf("extractTLSState failed on a live TLS 1.3 conn (reflection broken on %s): %v",
			"this Go toolchain", err)
	}
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("state.Version 0x%04x, want TLS 1.3", state.Version)
	}
	switch state.CipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
	default:
		t.Fatalf("unexpected cipher suite 0x%04x", state.CipherSuite)
	}

	// Traffic secrets must be present and sized to the suite's hash so that
	// deriveKeys downstream produces a correctly sized key/iv.
	if len(state.InTrafficSecret) == 0 || len(state.OutTrafficSecret) == 0 {
		t.Fatal("traffic secrets not extracted")
	}
	key, iv, err := deriveKeys(state.OutTrafficSecret, state.CipherSuite)
	if err != nil {
		t.Fatalf("deriveKeys from extracted secret: %v", err)
	}
	if len(iv) != 12 || len(key) == 0 {
		t.Fatalf("derived key/iv sizes wrong: key=%d iv=%d", len(key), len(iv))
	}
}

func TestExtractTLSStateRejectsTLS12(t *testing.T) {
	client, _ := tls13Pair(t, tls.VersionTLS12)
	if client.ConnectionState().Version != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2, got 0x%04x", client.ConnectionState().Version)
	}
	if _, err := extractTLSState(client); err == nil {
		t.Fatal("extractTLSState must reject non-TLS-1.3 connections")
	}
}

// TestEnableNonTCPFallsBack: a *tls.Conn over net.Pipe has no *net.TCPConn
// underneath, so Enable must give up and return nil while counting a fallback.
// The fallback counter moving is the positive control that Enable actually ran
// its unwrap path rather than short-circuiting elsewhere.
func TestEnableNonTCPFallsBack(t *testing.T) {
	client, _ := tls13Pair(t, tls.VersionTLS13)
	_, before := Stats()
	got := Enable(client)
	_, after := Stats()

	if got != nil {
		t.Fatalf("Enable over non-TCP conn returned %v, want nil", got)
	}
	if after <= before {
		t.Fatalf("fallback counter did not advance: before=%d after=%d", before, after)
	}
}

func TestTryEnableUnenamblableTLSReturnsOriginal(t *testing.T) {
	client, _ := tls13Pair(t, tls.VersionTLS13)
	got := TryEnable(client, "unit-test")
	if got != net.Conn(client) {
		t.Fatalf("TryEnable should return the original *tls.Conn when kTLS can't engage; got %T", got)
	}
}

func TestSupportedAndStatsCallable(t *testing.T) {
	_ = Supported() // must not panic; value depends on host kernel
	en, fb := Stats()
	if en < 0 || fb < 0 {
		t.Fatalf("negative stats: enabled=%d fallback=%d", en, fb)
	}
}
