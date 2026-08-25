package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"os"
)

// The TLS profile for the shared listener.
//
// This config serves everything that is not REALITY: the stego, morph,
// websocket-padded, http-polling and anti-probe strategies, plus whatever a
// scanner sends. It is also, therefore, what a scanner measures.

// classicCurves is the key-exchange group list we use by default, and
// hybridCurves the one we use for the donors that really do negotiate ML-KEM.
//
// Naming groups explicitly is what removes the hybrids from the default. In Go,
// CurvePreferences filters rather than orders: the defaults keep their own
// order and anything absent from the list is dropped, so listing the classics
// is enough. Left unset - which is how it was - the default puts
// X25519MLKEM768 first and we select it.
//
// What that cost: our front answered with a 1221-byte plaintext ServerHello
// where eleven of thirteen donors send 133. The extra 1088 bytes are the ML-KEM
// key, in the clear. A connection claiming SNI=yandex.ru and replying with a
// post-quantum key differs from the real yandex on the first response packet -
// no statistics, no decryption, no active probe needed.
//
// What we give up, deliberately rather than by oversight: this config is the
// only confidentiality layer for stego, morph, websocket-padded, http-polling
// and anti-probe, so those lose their hedge against record-now-decrypt-later.
// We accept that because a post-quantum group inside a mimicry layer is a
// beacon rather than a defence: it identifies us today, cheaply, against an
// adversary who does not have a quantum computer yet. The place for
// post-quantum key exchange is inside the tunnel, under the AEAD, where an
// observer cannot see which groups we chose.
//
// The exception is per donor, not per purpose. Two names in the pool negotiate
// ML-KEM for real, and under those we do too - see keyExchangeFor.
var (
	classicCurves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	hybridCurves  = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
)

// curvePreferencesFor returns the groups to offer under a given SNI. Both the
// shared listener and the B1 transport call this, from the one table, so the
// two paths cannot answer differently on the same port.
func curvePreferencesFor(sni string) []tls.CurveID {
	if keyExchangeFor(sni) == kxHybrid {
		return hybridCurves
	}
	return classicCurves
}

// tlsProfile is one node's variant of the shared TLS configuration.
//
// Nine fronts across four servers in two countries currently produce a
// bit-identical JARM, so a single request ties the whole fleet together.
// Replacing certificates does not move it - JARM fingerprints the behaviour of
// the stack, not the contents of the certificate, and that was measured rather
// than assumed.
//
// Be clear about what varying this does and does not buy. A per-node
// fingerprint does NOT make a node look like a donor. It stops one query from
// linking the fleet, which lowers blast radius and nothing more. Making our
// JARM resemble a donor's is not achievable cheaply: our fingerprint carries
// zeros on probes 4 through 8, meaning we answer those with no ServerHello at
// all while donors answer. To answer them we would have to accept the odd
// version and cipher combinations those probes offer - deliberately widening
// the surface and weakening the configuration to look prettier. That is a bad
// trade and this does not make it.
//
// The real fix is that an unauthenticated probe never reaches our TLS stack:
// the donor fallback in B1 and the mirroring in B1.5. This is a stopgap and
// does not replace them.
type tlsProfile struct {
	name       string
	minVersion uint16
	// cipherSuites applies to TLS 1.2 only. Go does not let TLS 1.3 suites be
	// configured, which is why half the JARM space is out of reach by design.
	cipherSuites []uint16
}

// tlsProfiles are the variants a node can land on.
//
// Every one of them holds the floor: MinVersion never below TLS 1.2, and the
// cipher lists are subsets of what Go already offers - no suite here is one Go
// would not have used anyway. The variation comes from which subset, and from
// whether the node answers TLS 1.2 probes at all.
//
// Ten is plenty. The goal is not a unique fingerprint per node, it is that the
// fingerprint stops being shared.
var tlsProfiles = []tlsProfile{
	{name: "tls13-only", minVersion: tls.VersionTLS13},
	{name: "tls12-ecdsa-aes", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}},
	{name: "tls12-rsa-aes", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}},
	{name: "tls12-chacha", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}},
	{name: "tls12-aes128-both", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}},
	{name: "tls12-aes256-both", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}},
	{name: "tls12-mixed-ecdsa", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}},
	{name: "tls12-mixed-rsa", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}},
	{name: "tls12-wide", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}},
	{name: "tls12-aes-chacha-rsa", minVersion: tls.VersionTLS12, cipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}},
}

// selectTLSProfile picks a node's variant from its seed.
//
// Deterministic, because a node whose fingerprint changes on restart has grown
// a new signal of its own: a host that looks like a different server every time
// it reboots is more interesting than one that looks the same.
func selectTLSProfile(seed string) tlsProfile {
	sum := sha256.Sum256([]byte(seed))
	idx := binary.BigEndian.Uint64(sum[:8]) % uint64(len(tlsProfiles))
	return tlsProfiles[idx]
}

// nodeSeed returns the value that fixes this node's profile.
//
// The listen address is part of it so that two fronts on one host still differ,
// which is the case we actually have: several ports on one server.
func nodeSeed(cfg *Config) string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown-host"
	}
	return host + "|" + cfg.ListenAddr
}

// buildTLSProfile assembles the shared listener's TLS configuration.
//
// Two configurations, built once and reused: the classic one, and the hybrid
// one for the two donors that negotiate ML-KEM. GetConfigForClient picks
// between them by the name the client asked for, which is the only input that
// decision is allowed to have.
func buildTLSProfile(cfg *Config, cert tls.Certificate) *tls.Config {
	profile := selectTLSProfile(nodeSeed(cfg))

	base := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       profile.minVersion,
		CipherSuites:     profile.cipherSuites,
		CurvePreferences: classicCurves,
	}

	hybrid := base.Clone()
	hybrid.CurvePreferences = hybridCurves

	base.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if keyExchangeFor(chi.ServerName) == kxHybrid {
			return hybrid, nil
		}
		// nil keeps the configuration the handshake started with, so the common
		// case costs nothing.
		return nil, nil
	}
	return base
}
