package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

// stdlibHello runs a crypto/tls client handshake over a pipe and returns the
// ClientHello handshake message it sent (no record header).
func stdlibHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _ = tls.Client(client, cfg).Handshake() }()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return body
}

func taggedConfig(secret []byte) *tls.Config {
	return &tls.Config{
		ServerName:         "www.google.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		Rand:               NewFallbackTagRand(secret),
	}
}

// TestFallbackTagLandsInTheStdlibSessionID drives the real crypto/tls client:
// the session_id it puts on the wire opens with the secret's key, the random
// is not the tag, and two handshakes carry two different tags.
func TestFallbackTagLandsInTheStdlibSessionID(t *testing.T) {
	secret := []byte("fallback-tag-secret")
	key := DeriveFallbackTagKey(secret)

	var seen [][AuthSessionIDLen]byte
	for range 2 {
		before := time.Now().Unix()
		hello := stdlibHello(t, taggedConfig(secret))
		sid, err := SessionIDFrom(hello)
		if err != nil {
			t.Fatal(err)
		}
		at, ok := key.Open(sid)
		if !ok {
			t.Fatal("the session_id crypto/tls sent is not a tag of the secret")
		}
		if int64(at) < before || int64(at) > time.Now().Unix() {
			t.Fatalf("tag time %d outside the handshake [%d, now]", at, before)
		}
		var random [32]byte
		copy(random[:], hello[6:38])
		if _, ok := key.Open(random); ok {
			t.Fatal("ClientHello.random carries a tag too")
		}
		seen = append(seen, sid)
	}
	if seen[0] == seen[1] {
		t.Fatal("two handshakes sent the same session_id")
	}

	// A reader serves one handshake. Reused, the second hello must carry no
	// tag rather than a repeated one.
	cfg := taggedConfig(secret)
	_ = stdlibHello(t, cfg)
	sid, _ := SessionIDFrom(stdlibHello(t, cfg))
	if _, ok := key.Open(sid); ok {
		t.Fatal("a spent reader tagged a second handshake")
	}
}

// TestFallbackTagKeysDoNotCross: another secret's key, and the B1 short ID of
// the same secret, do not open a tag.
func TestFallbackTagKeysDoNotCross(t *testing.T) {
	key := DeriveFallbackTagKey([]byte("alice"))
	tag, err := FallbackTag(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := DeriveFallbackTagKey([]byte("bob")).Open(tag); ok {
		t.Fatal("bob's key opened alice's tag")
	}
	id := ShortIDFor([]byte("alice"))
	if bytes.Equal(key[:len(id)], id[:]) {
		t.Fatal("the tag key and the B1 short ID come out of one derivation")
	}
	for i := range tag {
		flipped := tag
		flipped[i] ^= 0x80
		if _, ok := key.Open(flipped); ok {
			t.Fatalf("a tag with byte %d flipped still opens", i)
		}
	}
}

// TestFallbackTagLooksLikeRandom compares the shape of the field with what it
// replaces (verification rule 3): every byte position over many tags made in
// the same second is as flat as crypto/rand. The masked time is the part at
// risk, so the control runs the same check on tags whose time is not masked
// and requires it to fail.
func TestFallbackTagLooksLikeRandom(t *testing.T) {
	const n = 4096
	key := DeriveFallbackTagKey([]byte("shape"))
	now := time.Unix(1_800_000_000, 0)

	sample := func(gen func() [AuthSessionIDLen]byte) [][AuthSessionIDLen]byte {
		out := make([][AuthSessionIDLen]byte, n)
		for i := range out {
			out[i] = gen()
		}
		return out
	}
	tags := sample(func() [AuthSessionIDLen]byte {
		tag, err := FallbackTag(key, now)
		if err != nil {
			t.Fatal(err)
		}
		return tag
	})
	random := sample(func() (b [AuthSessionIDLen]byte) { _, _ = rand.Read(b[:]); return })
	plainTime := sample(func() [AuthSessionIDLen]byte {
		tag, _ := FallbackTag(key, now)
		binary.BigEndian.PutUint32(tag[fallbackTagNonceLen:], uint32(now.Unix()))
		return tag
	})

	worst := func(s [][AuthSessionIDLen]byte) (pos int, chi float64) {
		for p := range AuthSessionIDLen {
			var bins [256]float64
			for _, v := range s {
				bins[v[p]]++
			}
			x := 0.0
			for _, c := range bins {
				d := c - n/256.0
				x += d * d / (n / 256.0)
			}
			if x > chi {
				pos, chi = p, x
			}
		}
		return
	}
	// 255 degrees of freedom: mean 255, sd ~22.6. 400 is ~6 sd out.
	const limit = 400
	if p, chi := worst(random); chi > limit {
		t.Fatalf("crypto/rand itself fails the check (byte %d, chi2 %.0f): the threshold is wrong", p, chi)
	}
	if p, chi := worst(plainTime); chi <= limit {
		t.Fatalf("an unmasked time passes the check (byte %d, chi2 %.0f): it cannot see a static field", p, chi)
	}
	if p, chi := worst(tags); chi > limit {
		t.Fatalf("tag byte %d is not flat over one second (chi2 %.0f)", p, chi)
	}
	seen := make(map[[AuthSessionIDLen]byte]bool, n)
	for _, tag := range tags {
		if seen[tag] {
			t.Fatal("a tag repeated")
		}
		seen[tag] = true
	}
}

// TestFallbackTagRandTagsOnlyTheSessionIDRead: reads that do not come from
// makeClientHello get crypto/rand however many there are, so the tag cannot
// end up in a key or a nonce whatever order crypto/tls draws them in.
func TestFallbackTagRandTagsOnlyTheSessionIDRead(t *testing.T) {
	key := DeriveFallbackTagKey([]byte("caller"))
	r := NewFallbackTagRand([]byte("caller"))
	for i := range 4 {
		var b [AuthSessionIDLen]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			t.Fatal(err)
		}
		if _, ok := key.Open(b); ok {
			t.Fatalf("read %d from outside crypto/tls came back as a tag", i)
		}
	}
}

// TestFallbackTagKeepsTheStdlibFingerprint (verification rule 8): the tag must
// not make the hello any less like the plain crypto/tls one it was. Same
// length, same extensions in the same order with the same body lengths; only
// the values crypto/tls randomises anyway may differ.
func TestFallbackTagKeepsTheStdlibFingerprint(t *testing.T) {
	shape := func(hello []byte) (n int, exts []string) {
		block, err := helloExtensions(hello)
		if err != nil {
			t.Fatal(err)
		}
		_ = walkExtensions(block, func(_ int, typ uint16, body []byte) bool {
			exts = append(exts, fmt.Sprintf("%04x/%d", typ, len(body)))
			return false
		})
		return len(hello), exts
	}
	plain := taggedConfig(nil)
	plain.Rand = nil
	n0, e0 := shape(stdlibHello(t, plain))
	n1, e1 := shape(stdlibHello(t, WithFallbackTag(plain, []byte("fingerprint"))))
	if n0 != n1 || !slices.Equal(e0, e1) {
		t.Fatalf("tagged hello differs from plain crypto/tls:\nplain  %d %v\ntagged %d %v", n0, e0, n1, e1)
	}
	if len(e0) < 8 {
		t.Fatalf("only %d extensions parsed - the comparison sees nothing", len(e0))
	}
}
