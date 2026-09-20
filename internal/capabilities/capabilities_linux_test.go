//go:build linux

package capabilities

import "testing"

func TestParseCapEff(t *testing.T) {
	for _, c := range []struct {
		name      string
		status    string
		wantAdmin bool
		wantRaw   bool
	}{
		// Positive controls: bits set in the mask must be detected.
		{"both set", "Name:\tx\nCapEff:\t0000000000003000\n", true, true},
		{"admin only (bit12)", "CapEff:\t0000000000001000\n", true, false},
		{"raw only (bit13)", "CapEff:\t0000000000002000\n", false, true},
		{"full mask", "CapEff:\t000001ffffffffff\n", true, true},
		// Negative / boundary.
		{"empty mask", "CapEff:\t0000000000000000\n", false, false},
		{"no capeff line", "Name:\tx\nUid:\t0\n", false, false},
		{"malformed hex", "CapEff:\tnothex\n", false, false},
		{"leading space trimmed", "CapEff:\t   0000000000001000  \n", true, false},
		{"other cap bits ignored (bits 0-11)", "CapEff:\t0000000000000fff\n", false, false},
	} {
		gotAdmin, gotRaw := parseCapEff([]byte(c.status))
		if gotAdmin != c.wantAdmin || gotRaw != c.wantRaw {
			t.Errorf("%s: parseCapEff = (admin=%v, raw=%v), want (admin=%v, raw=%v)",
				c.name, gotAdmin, gotRaw, c.wantAdmin, c.wantRaw)
		}
	}
}
