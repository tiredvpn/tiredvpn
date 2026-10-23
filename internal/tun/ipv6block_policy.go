package tun

// wantsIPv6Block reports whether this device should carry the leak block: the
// policy asks for it, there is an interface to key the table on, and the
// operator has not taken IPv6 routing over themselves. An unnamed device is
// either torn down or was never configured.
//
// The -tun-routes6 condition is not a convenience switch. The block rejects
// every outbound IPv6 packet that is not the tunnel's, which is the correct
// fallback precisely while the tunnel claims all of IPv6 — the half-defaults.
// Once the operator has named the destinations, the rest of IPv6 is theirs by
// construction and there is nothing there to leak; blocking it would only cut
// the host's own connectivity.
//
// The decision is platform-neutral (the tests of the policy run on every
// platform); only Linux installs the block.
func (t *TUNDevice) wantsIPv6Block() bool {
	return t.ipv6Policy.BlocksLeakedIPv6() && t.name != "" && !t.ipv6Routes.OperatorManaged()
}
