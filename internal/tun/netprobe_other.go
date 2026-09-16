//go:build !linux

package tun

// physicalGateAddrs is a Linux-only helper (netlink); elsewhere the caller
// falls back to public-resolver probes.
func physicalGateAddrs() []string { return nil }
