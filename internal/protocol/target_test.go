package protocol

import (
	"strings"
	"testing"
)

func TestMaxTargetLenKeepsPrefixOffModeBytes(t *testing.T) {
	// The first prefix byte of the longest valid target must stay below the
	// 0x02 TUN-mode marker.
	if MaxTargetLen>>8 >= 0x02 {
		t.Fatalf("MaxTargetLen %d gives prefix first byte 0x%02x", MaxTargetLen, MaxTargetLen>>8)
	}
	longest := "[" + strings.Repeat("a", MaxTargetHostLen) + "]:65535"
	if len(longest) != MaxTargetLen {
		t.Fatalf("longest valid target is %d bytes, MaxTargetLen says %d", len(longest), MaxTargetLen)
	}
	if err := ValidateTarget(longest); err != nil {
		t.Fatalf("longest valid target refused: %v", err)
	}
}

func TestValidateTargetBoundaries(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	ok := []string{
		"a:1", "example.com:443", "192.0.2.1:0", "[2001:db8::1]:443",
		a(255) + ":443", a(255) + ":65535", "[" + a(255) + "]:65535",
		":443", // empty host is a dial-time question, not a framing one
	}
	bad := []string{
		a(256) + ":443", "[" + a(256) + "]:443", a(508) + ":443",
		a(65529) + ":443", "example.com:65536", "example.com:000443",
		"example.com:https", "example.com:-1", "example.com:+443", "example.com:4_43",
		"example.com:", "example.com", "2001:db8::1:443", "",
	}
	for _, s := range ok {
		if err := ValidateTarget(s); err != nil {
			t.Errorf("ValidateTarget(%d bytes %.20q): %v, want nil", len(s), s, err)
		}
	}
	for _, s := range bad {
		if err := ValidateTarget(s); err == nil {
			t.Errorf("ValidateTarget(%d bytes %.20q): nil, want error", len(s), s)
		}
	}
}
