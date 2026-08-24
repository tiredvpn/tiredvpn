package server

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// tryREALITYB1 reports whether the connection was served by the B1 transport.
//
// This is the single entry point the dispatcher has into B1, and it is
// deliberately the only line stream B has to add to server.go: everything B1
// needs already reaches it through srvCtx (config, registry, store, TUN), so
// filling this in never means editing a shared file again.
//
// It also carries the shape B1.5 needs. The donor-mirroring modes arrive as
// srvCtx.cfg.REALITYMirrorMode and the eager dial they require happens inside
// this call, where the client address that decides "known source or not" is in
// hand - not in the dispatcher, which has no business knowing about donors.
//
// Returning false means "not mine": the caller falls through to the legacy
// REALITY path and then to plain TLS, so a stub here leaves behaviour exactly
// as it was. Implemented by task 005.
func tryREALITYB1(conn net.Conn, peekBuf []byte, srvCtx *serverContext, logger *log.Logger) bool {
	_, _, _, _ = conn, peekBuf, srvCtx, logger
	return false
}
