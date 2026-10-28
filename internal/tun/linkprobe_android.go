//go:build android

package tun

// linkFallbackProbes is what localLinkUp dials when no gateway was found. On
// Android the app is excluded from its own VPN (addDisallowedApplication, or
// absent from an allow list), so its sockets take the underlying network and
// a public resolver answering there says that network is up - the tunnel's
// routes, which make these addresses useless for this on a desktop, do not
// apply to it. The gateway is usually not found at all: the default route
// lives in a per-network table, and app netlink access is restricted.
var linkFallbackProbes = publicFallbackProbes
