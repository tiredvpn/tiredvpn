package capabilities

import "strings"

type Set struct {
	HasNetAdmin  bool
	HasNetRaw    bool
	HasTUNDevice bool
}

func (s Set) String() string {
	var have, miss []string

	label := func(ok bool, name string) {
		if ok {
			have = append(have, name)
		} else {
			miss = append(miss, name)
		}
	}

	label(s.HasNetAdmin, "CAP_NET_ADMIN")
	label(s.HasNetRaw, "CAP_NET_RAW")
	label(s.HasTUNDevice, "/dev/net/tun")

	var parts []string
	if len(have) > 0 {
		parts = append(parts, "have=["+strings.Join(have, ",")+"]")
	}
	if len(miss) > 0 {
		parts = append(parts, "missing=["+strings.Join(miss, ",")+"]")
	}
	return strings.Join(parts, " ")
}
