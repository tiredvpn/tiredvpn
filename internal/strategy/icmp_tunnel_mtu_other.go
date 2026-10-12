//go:build !linux

package strategy

import "net"

// icmpRouteMTU is not implemented here; packets fall back to MaxPayloadSize.
func icmpRouteMTU(net.IP) int { return 0 }
