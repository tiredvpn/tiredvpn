//go:build !linux

package strategy

import "net"

// handshakeProgressed: no TCP_INFO here, so no handshake counts as under
// way, and a held attempt is cut at its share.
func handshakeProgressed(net.Conn) bool { return false }
