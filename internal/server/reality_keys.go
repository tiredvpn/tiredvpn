package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/tiredvpn/tiredvpn/internal/log"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// The server's static X25519 key pair.
//
// Under the legacy transport this pair was generated fresh on every process
// start and nothing ever did an ECDH against it — the public half went out in
// the ServerHello padding and no client read it, so a new key per restart cost
// nothing. B1 changes that: the session_id authentication key is derived from
// this pair, so a key that changes on restart drops every client at once.
//
// Hence the key becomes configuration. It is loaded once at startup and never
// rotated at runtime; the mutex guards the load against readers on the accept
// path, not against rotation.
var (
	serverREALITYPrivKey [32]byte
	serverREALITYPubKey  [32]byte
	realityKeyMu         sync.RWMutex
)

// errNoREALITYKey is returned when B1 is on but no static key is configured.
// Generating one silently would put us back where we started: a key that
// changes on restart and takes every client down with it.
var errNoREALITYKey = errors.New(
	"reality: -reality-b1 requires a static server key; generate one with `tiredvpn reality-keygen` " +
		"and set -reality-private-key (or TIREDVPN_REALITY_PRIVATE_KEY)")

// InitREALITYKeys loads the server's X25519 key pair.
//
// With B1 enabled the key comes from configuration and a missing one is fatal.
// With B1 off the old behaviour stands - a fresh pair per start - so upgrading
// a node that has not opted into B1 needs no new configuration.
func InitREALITYKeys(cfg *Config) error {
	realityKeyMu.Lock()
	defer realityKeyMu.Unlock()

	if !cfg.REALITYB1Enabled {
		privKey, pubKey, err := customtls.GenerateX25519KeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate reality keys: %w", err)
		}
		serverREALITYPrivKey = privKey
		serverREALITYPubKey = pubKey
		log.Info("REALITY server keys initialized (ephemeral, B1 disabled)")
		return nil
	}

	if cfg.REALITYPrivateKey == "" {
		return errNoREALITYKey
	}

	priv, pub, err := ParseREALITYPrivateKey(cfg.REALITYPrivateKey)
	if err != nil {
		return fmt.Errorf("reality: %w", err)
	}
	serverREALITYPrivKey = priv
	serverREALITYPubKey = pub

	// The public half is logged on purpose: it is what operators paste into
	// client configs, and having it in the startup log saves a round trip to
	// wherever the private key is kept.
	log.Info("REALITY server keys loaded (static, public key %s)", EncodeREALITYKey(pub))
	return nil
}

// REALITY donor-mirroring modes. See reality_mirror.go for what each one costs:
// "always" dials a donor for every connection including users, "adaptive" only
// for sources that have not authenticated recently, "off" never.
const (
	MirrorOff      = "off"
	MirrorAdaptive = "adaptive"
	MirrorAlways   = "always"
)

// validateREALITYConfig checks the REALITY settings that have to be right
// before the listener opens. Refusing to start beats discovering a typo when
// the first client fails to connect.
func validateREALITYConfig(cfg *Config) error {
	switch cfg.REALITYMirrorMode {
	case "":
		cfg.REALITYMirrorMode = MirrorAdaptive
	case MirrorOff, MirrorAdaptive, MirrorAlways:
	default:
		return fmt.Errorf("unknown -reality-mirror %q, want %s, %s or %s",
			cfg.REALITYMirrorMode, MirrorOff, MirrorAdaptive, MirrorAlways)
	}

	if !cfg.REALITYB1Enabled && !cfg.REALITYLegacyEnabled {
		return errors.New("both -reality-b1 and -reality-legacy are off, no REALITY client could connect")
	}

	if cfg.REALITYMaxTimeDiff < 0 {
		return fmt.Errorf("-reality-max-time-diff must not be negative, got %d", cfg.REALITYMaxTimeDiff)
	}

	logMirrorMode(cfg.REALITYMirrorMode)

	if cfg.REALITYMinClientVer != "" {
		if _, err := parseClientVersion(cfg.REALITYMinClientVer); err != nil {
			return fmt.Errorf("-reality-min-client-ver %q: %w", cfg.REALITYMinClientVer, err)
		}
	}

	return nil
}

// parseClientVersion turns "X.Y.Z" into the three bytes a client puts in its
// authentication payload.
//
// Checked at startup rather than per connection: a version the server cannot
// parse would otherwise be applied as "no minimum" on every connection, so a
// typo in the flag would look exactly like the check working and passing
// everyone.
func parseClientVersion(s string) ([3]byte, error) {
	var out [3]byte
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, errors.New("want three dot-separated numbers, X.Y.Z")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("component %q is not a number", p)
		}
		if n < 0 || n > 255 {
			return out, fmt.Errorf("component %d is out of range 0-255", n)
		}
		out[i] = byte(n)
	}
	return out, nil
}

// realityStaticKeys returns the loaded key pair. Callers on the accept path use
// this instead of reading the globals directly, so the locking lives in exactly
// one place.
func realityStaticKeys() (priv, pub [32]byte) {
	realityKeyMu.RLock()
	defer realityKeyMu.RUnlock()
	return serverREALITYPrivKey, serverREALITYPubKey
}

// EncodeREALITYKey renders a key as unpadded URL-safe base64, the same encoding
// Xray uses for REALITY keys, so a value copied from one config reads the same
// in the other.
func EncodeREALITYKey(key [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(key[:])
}

// decodeREALITYKey accepts any of the four base64 alphabets an operator might
// paste. We emit raw-url and read whatever arrives: a padded key copied out of
// a JSON config should not turn into a startup failure that reads like a
// corrupt key.
func decodeREALITYKey(s string) ([]byte, error) {
	// Delegates to the shared implementation so the client, which reads the
	// public half, accepts exactly the same alphabets.
	raw, err := customtls.DecodeKeyBase64(s)
	if err != nil {
		return nil, errors.New("private key is not valid base64")
	}
	return raw, nil
}

// ParseREALITYPrivateKey decodes a base64 private key and derives its public
// half, so the two can never disagree: the server always advertises the key it
// actually holds.
func ParseREALITYPrivateKey(s string) (priv, pub [32]byte, err error) {
	raw, err := decodeREALITYKey(s)
	if err != nil {
		return priv, pub, err
	}
	if len(raw) != 32 {
		return priv, pub, fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	copy(priv[:], raw)

	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("private key is not a usable X25519 scalar: %w", err)
	}
	copy(pub[:], derived)
	return priv, pub, nil
}

// GenerateREALITYKeyPair returns a fresh key pair already encoded for config
// files. It backs `tiredvpn reality-keygen`.
func GenerateREALITYKeyPair() (privB64, pubB64 string, err error) {
	priv, _, err := customtls.GenerateX25519KeyPair()
	if err != nil {
		return "", "", err
	}
	// Derive the public half through the same path the loader uses, so keygen
	// and startup can never disagree about what public key a private key has.
	priv, pub, err := ParseREALITYPrivateKey(EncodeREALITYKey(priv))
	if err != nil {
		return "", "", err
	}
	return EncodeREALITYKey(priv), EncodeREALITYKey(pub), nil
}
