package main

import "testing"

// -protect-proto is how the app says it speaks the SCM_RIGHTS protect
// protocol. Anything but a clean 1 or 2 must leave the core on protocol 1:
// guessing v2 for an app that does not speak it would fail every protect.
func TestParseClientArgsProtectProto(t *testing.T) {
	base := []string{"-server", "203.0.113.10:443", "-secret", "s", "-protect-path", "/tmp/p.sock", "-tun"}
	cases := []struct {
		name  string
		extra []string
		want  int
	}{
		{"absent", nil, 0},
		{"two", []string{"-protect-proto", "2"}, 2},
		{"one", []string{"-protect-proto", "1"}, 1},
		{"unsupported", []string{"-protect-proto", "3"}, 0},
		{"garbage", []string{"-protect-proto", "dup"}, 0},
		{"missing value", []string{"-protect-proto"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseClientArgs(append(append([]string{}, base...), tc.extra...))
			if err != nil {
				t.Fatalf("parseClientArgs: %v", err)
			}
			if cfg.ProtectProto != tc.want {
				t.Errorf("ProtectProto = %d, want %d", cfg.ProtectProto, tc.want)
			}
			if cfg.ProtectPath != "/tmp/p.sock" {
				t.Errorf("ProtectPath = %q, the flag must not disturb its neighbours", cfg.ProtectPath)
			}
		})
	}
}
