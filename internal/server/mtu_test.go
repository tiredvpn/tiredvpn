package server

import (
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

func TestResolveTunMTU(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero falls back to default", 0, tun.DefaultMTU},
		{"negative falls back to default", -1, tun.DefaultMTU},
		{"explicit 1280", 1280, 1280},
		{"explicit 1500", 1500, 1500},
		{"jumbo 9000", 9000, 9000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTunMTU(&Config{TunMTU: c.in}); got != c.want {
				t.Errorf("resolveTunMTU(%d) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestNegotiateMTU(t *testing.T) {
	cases := []struct {
		name      string
		clientMTU int
		serverMTU int
		want      int
	}{
		{"legacy client (0) takes server MTU", 0, 1500, 1500},
		{"client smaller wins", 1280, 1500, 1280},
		{"server smaller caps client", 1500, 1280, 1280},
		{"equal", 1500, 1500, 1500},
		{"large client capped to server", 9000, 1500, 1500},
		{"both default", 1280, 1280, 1280},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := negotiateMTU(c.clientMTU, c.serverMTU); got != c.want {
				t.Errorf("negotiateMTU(%d, %d) = %d, want %d", c.clientMTU, c.serverMTU, got, c.want)
			}
		})
	}
}
