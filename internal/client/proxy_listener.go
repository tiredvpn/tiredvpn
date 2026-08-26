package client

import (
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Labels for the two local proxy sockets, so the "listening" and "disabled"
// lines for one socket always name it the same way.
const (
	socksProxyLabel = "SOCKS5/HTTP proxy"
	httpProxyLabel  = "HTTP proxy"
)

// startProxy opens a local proxy listener and logs what actually happened:
// the address the socket is bound to on success, and the fact that the proxy is
// off when no address is configured. A failed listen logs nothing here — the
// callers differ on how loud that is (a warning in TUN mode, fatal in proxy
// mode) — but in no case is a listening claim made for a socket that is not
// listening.
//
// The bound address comes from the listener rather than the config string, for
// the same reason the tunnel address does: ":0" and an empty host are resolved
// by the kernel, and the config is not the fact.
//
// Returns (nil, nil) when addr is empty. Callers must handle that case; there
// is deliberately no listener to fall through with.
func startProxy(addr, label string) (net.Listener, error) {
	if addr == "" {
		log.Info("%s disabled (no listen address configured)", label)
		return nil, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Info("%s listening on %s", label, l.Addr())
	return l, nil
}
