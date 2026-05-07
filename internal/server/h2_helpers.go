package server

import (
	"errors"
	"io"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"

	"golang.org/x/net/http2"
)

// readH2Preface reads and validates the 24-byte HTTP/2 client preface from
// conn. Must be called BEFORE kTLS Enable on the server side: the preface
// bytes may be sitting in the TLS stack's read buffer after handshake, and
// kTLS taking over the socket would lose them.
func readH2Preface(conn net.Conn, logger *log.Logger) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		logger.Debug("Failed to read HTTP/2 preface: %v", err)
		return err
	}
	if string(preface) != http2.ClientPreface {
		logger.Debug("Invalid HTTP/2 preface: % x", preface)
		return errors.New("invalid HTTP/2 preface")
	}
	return nil
}

// newH2Framer constructs an HTTP/2 framer over conn and writes the initial
// server SETTINGS frame. Safe to call after kTLS Enable — the framer holds
// a permanent reference to conn for subsequent frame I/O, so the conn
// passed in must be the final post-Enable wrapper.
//
// AllowIllegalReads / AllowIllegalWrites are set true to mirror
// initH2Framer's tolerance for client variants that occasionally emit
// non-spec-compliant frames; we have observed this in the wild and the
// stego layer takes care of validating frame contents itself.
func newH2Framer(conn net.Conn, logger *log.Logger) (*http2.Framer, error) {
	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalReads = true
	framer.AllowIllegalWrites = true
	if err := framer.WriteSettings(); err != nil {
		logger.Debug("Failed to write SETTINGS: %v", err)
		return nil, err
	}
	return framer, nil
}
