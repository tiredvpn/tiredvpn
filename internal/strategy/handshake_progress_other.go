//go:build !linux

package strategy

import "net"

// handshakeProgressed: no TCP_INFO here, so progress cannot be seen, and
// every handshake counts as under way - a held attempt runs past its share
// as an unheld one does. Counted as stalled, every held attempt was cut at
// its share on macOS and Windows, a slow live server included (P3-3 of the
// round-11 review). The price: there, a route that drops the first flight
// is not left any faster under swallow pressure than before round 15.
func handshakeProgressed(net.Conn) bool { return true }
