package client

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// localIPSource supplies the address the tunnel interface actually carries.
// *tun.VPNClient implements it; tests supply a fake.
type localIPSource interface {
	LocalIP() net.IP
}

// logVPNStarted announces the live tunnel.
//
// The address comes from the tunnel, never from cfg.TunIP. cfg.TunIP is what
// was *requested* at handshake time; by the time this runs the exit has already
// assigned an address and the TUN device has been moved onto it, so on any
// pool-assigning exit the two differ on every start. Reporting the request as
// if it were the fact once produced a diagnosis of two clients sharing one
// tunnel address, which had never happened.
//
// cfg is passed in whole, rather than just the name, so that this substitution
// lives inside a function a test can drive: the wrong value is reachable here,
// and TestLogVPNStartedPrintsAssignedNotRequested fails the moment it is used.
func logVPNStarted(cfg *Config, tunnel localIPSource) {
	log.Info("VPN started on %s (IP: %s)", cfg.TunName, tunnel.LocalIP())
}
