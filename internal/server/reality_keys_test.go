package server

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestGenerateREALITYKeyPairAgrees checks that the two halves keygen prints
// belong together. They travel to opposite ends of a deployment and are never
// compared again until a client fails to connect, so the pairing is verified
// here, against curve25519 directly rather than against our own derivation.
func TestGenerateREALITYKeyPairAgrees(t *testing.T) {
	t.Parallel()

	for range 8 {
		privB64, pubB64, err := GenerateREALITYKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		privRaw, err := base64.RawURLEncoding.DecodeString(privB64)
		if err != nil {
			t.Fatalf("private key is not raw-url base64: %v", err)
		}
		if len(privRaw) != 32 {
			t.Fatalf("private key is %d bytes, want 32", len(privRaw))
		}

		want, err := curve25519.X25519(privRaw, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if got := base64.RawURLEncoding.EncodeToString(want); got != pubB64 {
			t.Fatalf("printed public key %s, but the private key derives %s", pubB64, got)
		}
	}
}

func TestParseREALITYPrivateKey(t *testing.T) {
	t.Parallel()

	privB64, pubB64, err := GenerateREALITYKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("accepts every base64 alphabet", func(t *testing.T) {
		// An operator pasting a padded or standard-alphabet key should get a
		// working server, not an error that reads like key corruption.
		for name, enc := range map[string]*base64.Encoding{
			"raw url": base64.RawURLEncoding,
			"raw std": base64.RawStdEncoding,
			"url":     base64.URLEncoding,
			"std":     base64.StdEncoding,
		} {
			_, pub, err := ParseREALITYPrivateKey(enc.EncodeToString(raw))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if EncodeREALITYKey(pub) != pubB64 {
				t.Fatalf("%s: derived a different public key", name)
			}
		}
	})

	t.Run("rejects bad input", func(t *testing.T) {
		for _, tc := range []struct{ name, key string }{
			{"not base64", "!!!!"},
			{"too short", base64.RawURLEncoding.EncodeToString(raw[:31])},
			{"too long", base64.RawURLEncoding.EncodeToString(append(raw, 0))},
			{"empty", ""},
		} {
			if _, _, err := ParseREALITYPrivateKey(tc.key); err == nil {
				t.Fatalf("%s: accepted", tc.name)
			}
		}
	})
}

// TestInitREALITYKeysStable is the point of making the key configuration: the
// same key must survive a restart, because the B1 session_id key is derived
// from it and a new one drops every client at once.
func TestInitREALITYKeysStable(t *testing.T) {
	privB64, pubB64, err := GenerateREALITYKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{REALITYB1Enabled: true, REALITYPrivateKey: privB64}

	var first [32]byte
	for i := range 2 { // two "restarts"
		if err := InitREALITYKeys(cfg); err != nil {
			t.Fatal(err)
		}
		_, pub := realityStaticKeys()
		if EncodeREALITYKey(pub) != pubB64 {
			t.Fatalf("loaded public key does not match the configured private key")
		}
		if i == 0 {
			first = pub
		} else if pub != first {
			t.Fatal("public key changed across restarts")
		}
	}
}

func TestInitREALITYKeysRequiresKeyWithB1(t *testing.T) {
	err := InitREALITYKeys(&Config{REALITYB1Enabled: true})
	if err == nil {
		t.Fatal("started with B1 on and no key")
	}
	if !errors.Is(err, errNoREALITYKey) {
		t.Fatalf("got %v, want errNoREALITYKey", err)
	}
	// The message has to say what to run; an operator hitting this has no other
	// clue where a REALITY key comes from.
	if !strings.Contains(err.Error(), "reality-keygen") {
		t.Fatalf("error does not name the keygen subcommand: %v", err)
	}
}

// TestInitREALITYKeysWithoutB1 covers the upgrade path: a node that has not
// opted into B1 must keep starting with no new configuration at all.
func TestInitREALITYKeysWithoutB1(t *testing.T) {
	cfg := &Config{REALITYB1Enabled: false}
	if err := InitREALITYKeys(cfg); err != nil {
		t.Fatalf("legacy-only server failed to start: %v", err)
	}
	_, firstPub := realityStaticKeys()

	if err := InitREALITYKeys(cfg); err != nil {
		t.Fatal(err)
	}
	_, secondPub := realityStaticKeys()

	// And it keeps the old behaviour, a fresh pair per start. Asserted rather
	// than assumed: if this ever becomes stable-by-accident, the B1 path is
	// probably reading the wrong branch.
	if firstPub == secondPub {
		t.Fatal("ephemeral key did not change between starts")
	}
}

func TestValidateREALITYConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		wantMod string // expected REALITYMirrorMode after validation
	}{
		{"empty mirror defaults to adaptive", Config{REALITYLegacyEnabled: true}, false, MirrorAdaptive},
		{"off", Config{REALITYLegacyEnabled: true, REALITYMirrorMode: MirrorOff}, false, MirrorOff},
		{"adaptive accepted early", Config{REALITYLegacyEnabled: true, REALITYMirrorMode: MirrorAdaptive}, false, MirrorAdaptive},
		{"always accepted early", Config{REALITYLegacyEnabled: true, REALITYMirrorMode: MirrorAlways}, false, MirrorAlways},
		{"typo rejected", Config{REALITYLegacyEnabled: true, REALITYMirrorMode: "adaptative"}, true, ""},
		{"both transports off", Config{}, true, ""},
		{"negative time diff", Config{REALITYLegacyEnabled: true, REALITYMaxTimeDiff: -1}, true, ""},
		{"b1 only is fine", Config{REALITYB1Enabled: true}, false, MirrorAdaptive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := validateREALITYConfig(&cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("accepted an invalid config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.REALITYMirrorMode != tt.wantMod {
				t.Fatalf("mirror mode = %q, want %q", cfg.REALITYMirrorMode, tt.wantMod)
			}
		})
	}
}
