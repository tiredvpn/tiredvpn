package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
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

// TestFallbackTagOpenerAgreesWithTheKey: the prepared opener the server uses
// gives the key's answer on its own tags, on another key's and on noise.
func TestFallbackTagOpenerAgreesWithTheKey(t *testing.T) {
	key := DeriveFallbackTagKey([]byte("opener"))
	o := NewFallbackTagOpener(key)
	other := DeriveFallbackTagKey([]byte("someone else"))
	for i := range 200 {
		var sid [AuthSessionIDLen]byte
		switch i % 3 {
		case 0:
			sid, _ = FallbackTag(key, time.Unix(int64(1_800_000_000+i), 0))
		case 1:
			sid, _ = FallbackTag(other, time.Now())
		default:
			_, _ = rand.Read(sid[:])
		}
		at1, ok1 := key.Open(sid)
		at2, ok2 := o.Open(sid)
		if ok1 != ok2 || at1 != at2 {
			t.Fatalf("case %d: key says (%d, %v), opener (%d, %v)", i%3, at1, ok1, at2, ok2)
		}
		if i%3 == 0 && !ok2 {
			t.Fatal("the opener rejected its own key's tag")
		}
	}
}

// TestTheTagSelfCheck is P3-11 of the round-5 review: the tag's placement
// rests on crypto/tls internals, and a client that failed to place it got no
// signal. The self-check finds the tag in this build's ClientHello; and when
// it does not, the first tagged config says so in the log.
func TestTheTagSelfCheck(t *testing.T) {
	if !placesFallbackTag() {
		t.Fatal("the self-check does not find the tag this build places")
	}

	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	old := placesFallbackTagFn
	placesFallbackTagFn = func() bool { return false }
	fallbackTagCheck = sync.Once{}
	t.Cleanup(func() { placesFallbackTagFn = old; fallbackTagCheck = sync.Once{} })
	_ = WithFallbackTag(&tls.Config{}, []byte("x"))
	if !strings.Contains(out.String(), "does not take it into the ClientHello") {
		t.Fatalf("a failed self-check left no trace in the log: %q", out.String())
	}
}

// TestWeakSecret: P2-1 of the round-5 review recovered "pass-424242" from one
// tag in about a second. What an operator types by hand is flagged; a random
// secret is not.
func TestWeakSecret(t *testing.T) {
	for _, tc := range []struct {
		secret string
		weak   bool
	}{
		{"pass-424242", true},
		{"Xq7#mP2$vL9@kR4", true}, // 15 bytes: rich, but short
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"correcthorsebattery", true}, // 19 lowercase: about 89 bits
		{"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", false},
		{"Xq7#mP2$vL9@kR4!wN6&zT3*", false},
	} {
		if why, weak := WeakSecret([]byte(tc.secret)); weak != tc.weak {
			t.Errorf("%q: weak=%v (%s), want %v", tc.secret, weak, why, tc.weak)
		}
	}
}
