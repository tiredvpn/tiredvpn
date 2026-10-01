package server

import (
	"net"
	"strconv"
	"testing"
)

// freeV6Ports reserves n loopback IPv6 ports and releases them, or skips the
// test when the host has no ::1.
func freeV6Ports(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	for range n {
		l, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback here: %v", err)
		}
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
		l.Close()
	}
	return ports
}

// TestMultiPortListener_IPv6Host: -listen [::]:995 with -port-range hands the
// listener the host "::". Spliced with "%s:%d" that became ":::995", every
// port failed to bind and the server came up with no listener at all.
func TestMultiPortListener_IPv6Host(t *testing.T) {
	t.Run("several ports", func(t *testing.T) {
		ports := freeV6Ports(t, 2)
		mpl, err := NewMultiPortListener("::1", ports)
		if err != nil {
			t.Fatalf("NewMultiPortListener(::1): %v", err)
		}
		defer mpl.Close()
		if mpl.NumPorts() != len(ports) {
			t.Fatalf("bound %d ports, want %d", mpl.NumPorts(), len(ports))
		}
	})
	t.Run("single port from range", func(t *testing.T) {
		port := freeV6Ports(t, 1)[0]
		ln, err := NewMultiPortListenerFromRange("::1", strconv.Itoa(port), 0)
		if err != nil {
			t.Fatalf("NewMultiPortListenerFromRange(::1): %v", err)
		}
		defer ln.Close()
		if got := ln.Addr().(*net.TCPAddr).Port; got != port {
			t.Fatalf("bound port %d, want %d", got, port)
		}
	})
}
