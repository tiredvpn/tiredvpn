package server

import (
	"fmt"
	"net"
)

// deriveListenAddrV6 builds the IPv6 listen address from the IPv4 -listen
// address, for deployments that did not spell -listen-v6 out explicitly.
//
// It exists because the previous default was the literal "[::]:995": a server
// told to listen on any other port still tried to open v6 on 995. Either that
// port was taken (no v6 entry at all, only a line in the log) or it was free
// and the process quietly opened a port nobody asked for — extra observable
// surface on a censorship-resistance box, visible only through `ss -ltn`.
//
// A derived address keeps the port and widens the host to the v6 wildcard.
// Returning an empty string with a non-nil error means "do not start the v6
// listener, and here is the reason to put in the log"; that is a diagnosable
// state, not a failure, so the caller logs and carries on with IPv4 only.
func deriveListenAddrV6(listenAddr string) (string, error) {
	if listenAddr == "" {
		return "", fmt.Errorf("-listen is empty, nothing to derive the IPv6 address from")
	}

	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("cannot parse -listen %q: %w", listenAddr, err)
	}
	// SplitHostPort accepts ":" and "1.2.3.4:" with an empty port; net.Listen
	// would read that as "any free port", which is never what an operator
	// means for the entry socket.
	if port == "" {
		return "", fmt.Errorf("-listen %q has no port", listenAddr)
	}

	// A host that is already an IPv6 literal means the operator addressed the
	// v6 side themselves in -listen. Deriving a second v6 socket from it would
	// be second-guessing that; -listen-v6 is the flag for saying otherwise.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "", fmt.Errorf("-listen %q is already an IPv6 address; set -listen-v6 explicitly to add a second IPv6 socket", listenAddr)
	}

	// Everything else — the empty host of ":443", the v4 wildcard, a concrete
	// v4 address, a hostname — becomes the v6 wildcard on the same port. For a
	// concrete v4 address such as 1.2.3.4:443 this is deliberately a widening:
	// that address has no v6 counterpart to bind, and the alternative (no v6 at
	// all) is what this whole change is undoing. An operator who needs the v6
	// socket pinned to one address says so with -listen-v6.
	return net.JoinHostPort("::", port), nil
}

// resolveListenAddrV6 returns the address the IPv6 listener should bind, and
// whether it was derived from -listen rather than given by the operator. An
// explicit -listen-v6 is passed through untouched, so existing deployments
// that spell it out keep their exact behavior.
func resolveListenAddrV6(cfg *Config) (addr string, derived bool, err error) {
	if cfg.ListenAddrV6 != "" {
		return cfg.ListenAddrV6, false, nil
	}
	addr, err = deriveListenAddrV6(cfg.ListenAddr)
	if err != nil {
		return "", false, err
	}
	return addr, true, nil
}
