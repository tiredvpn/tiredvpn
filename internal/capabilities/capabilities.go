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

	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		s.HasNetAdmin, s.HasNetRaw = parseCapEff(data)
	}

	return s
}

// parseCapEff scans /proc/<pid>/status content for the CapEff line and decodes
// the effective capability bitmask, reporting whether CAP_NET_ADMIN (bit 12)
// and CAP_NET_RAW (bit 13) are held. Missing line or malformed hex yields false.
func parseCapEff(status []byte) (netAdmin, netRaw bool) {
	for line := range strings.SplitSeq(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			if val, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64); err == nil {
				netAdmin = val&(1<<12) != 0
				netRaw = val&(1<<13) != 0
			}
			return netAdmin, netRaw
		}
	}
	return false, false
}
