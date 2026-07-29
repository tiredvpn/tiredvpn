//go:build linux

package capabilities

import (
	"os"
	"strconv"
	"strings"
)

func Probe() Set {
	s := Set{}

	if _, err := os.Stat("/dev/net/tun"); err == nil {
		s.HasTUNDevice = true
	}

	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
				hexVal := strings.TrimSpace(rest)
				val, err := strconv.ParseUint(hexVal, 16, 64)
				if err == nil {
					s.HasNetAdmin = val&(1<<12) != 0
					s.HasNetRaw = val&(1<<13) != 0
				}
				break
			}
		}
	}

	return s
}
