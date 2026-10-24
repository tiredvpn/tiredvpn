//go:build !linux && !darwin

package tun

// physicalGateAddrs has no routing table to read here; the caller falls back
// to public-resolver probes, and localLinkUp says it cannot tell.
func physicalGateAddrs() []string { return nil }
