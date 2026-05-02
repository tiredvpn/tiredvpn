package strategy

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// NewTestMorphedConnPair returns two MorphedConn endpoints connected via
// net.Pipe with shapers pre-installed and the application-layer Morph
// handshake skipped. It exists for cross-package integration tests that
// would otherwise deadlock on the synchronous handshake Write performed by
// NewMorphedConnWithShaper. The returned cleanup closes both pipe halves.
//
// This helper is intentionally not under build tag `test`: Go does not allow
// _test.go files to export symbols across packages. Production code paths
// should always use NewMorphedConn / NewMorphedConnWithShaper.
func NewTestMorphedConnPair(profile *TrafficProfile, clientShaper, serverShaper shaper.Shaper) (*MorphedConn, *MorphedConn, func()) {
	if clientShaper == nil {
		clientShaper = shaper.NoopShaper{}
	}
	if serverShaper == nil {
		serverShaper = shaper.NoopShaper{}
	}
	cliConn, srvConn := net.Pipe()
	client := &MorphedConn{Conn: cliConn, profile: profile, shaper: clientShaper}
	server := &MorphedConn{Conn: srvConn, profile: profile, shaper: serverShaper}
	cleanup := func() {
		_ = cliConn.Close()
		_ = srvConn.Close()
	}
	return client, server, cleanup
}
