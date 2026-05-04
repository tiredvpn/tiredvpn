package strategy

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// NewTestMorphedConnPairTCP is the loopback-TCP analogue of
// NewTestMorphedConnPair. Unlike net.Pipe (synchronous, end-to-end serialised
// per Write), a real TCP socket on 127.0.0.1 has kernel send/receive buffers
// of order ~BDP, which lets the pacer goroutine make forward progress while
// the producer is still issuing Writes. This reflects the deployment regime
// where shaper overhead must be measured. Cleanup closes both endpoints and
// the listener.
func NewTestMorphedConnPairTCP(profile *TrafficProfile, clientShaper, serverShaper shaper.Shaper) (*MorphedConn, *MorphedConn, func(), error) {
	if clientShaper == nil {
		clientShaper = shaper.NoopShaper{}
	}
	if serverShaper == nil {
		serverShaper = shaper.NoopShaper{}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, err
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c: c, err: err}
	}()
	cliConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		return nil, nil, nil, err
	}
	a := <-ch
	if a.err != nil {
		_ = cliConn.Close()
		_ = ln.Close()
		return nil, nil, nil, a.err
	}
	srvConn := a.c
	client := &MorphedConn{Conn: cliConn, profile: profile, shaper: clientShaper}
	server := &MorphedConn{Conn: srvConn, profile: profile, shaper: serverShaper}
	cleanup := func() {
		_ = client.Close()
		_ = server.Close()
		_ = ln.Close()
	}
	return client, server, cleanup, nil
}

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
