//go:build !linux
// +build !linux

package tun

import "fmt"

// SetupServerNAT is Linux-only (nftables/netlink); the server binary still
// has to build for other GOOS targets (see Makefile darwin targets for the
// combined client+server binary), so this stub keeps the build green while
// making it clear TUN server mode's NAT bootstrap isn't available here.
func SetupServerNAT(pool string, wanOverride string) error {
	if pool == "" {
		return nil
	}
	return fmt.Errorf("server TUN mode NAT auto-config is only supported on Linux")
}
