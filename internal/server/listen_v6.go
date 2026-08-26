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

	// A concrete IPv6 literal is a dead end, but not because of this function:
	// the main listener runs net.Listen("tcp4", ...), and tcp4 rejects an IPv6
	// address outright ("no suitable address found"), so the process never gets
	// this far. Report the reason rather than derive an address for a server
	// that will not start.
	//
	// The v6 wildcard is the opposite case and used to be lumped in with it, on
	// the assumption that deriving [::]:port would collide with the main socket.
	// Measured, and it does not: tcp4 with a wildcard host binds 0.0.0.0, and Go
	// sets IPV6_V6ONLY on every tcp6 socket, so the two coexist on one port.
	// Verified both halves directly — net.Listen("tcp4", "[::]:P") reports
	// 0.0.0.0:P, and a tcp6 listener on the same port opens alongside it without
	// error. Refusing to derive here would leave an operator who wrote -listen
	// [::]:997 — that is, who asked for both families — with no IPv6 entry at
	// all, which is the very failure this whole change exists to remove.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil && !ip.IsUnspecified() {
		return "", fmt.Errorf("-listen %q is an IPv6 address, which the IPv4 listener cannot bind; set -listen and -listen-v6 explicitly", listenAddr)
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
