package strategy

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The kernel's answer for loopback has to be the loopback interface MTU,
// capped at the 65535 an IPv4 packet can be; a wrong socket option or level
// would give a number with no relation to it.
func TestICMPRouteMTUMatchesLoopback(t *testing.T) {
	raw, err := os.ReadFile("/sys/class/net/lo/mtu")
	if err != nil {
		t.Skipf("no loopback MTU in sysfs: %v", err)
	}
	want, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	want = min(want, 65535)
	if got := icmpRouteMTU(net.IPv4(127, 0, 0, 1)); got != want {
		t.Fatalf("icmpRouteMTU(127.0.0.1) = %d, want lo MTU %d", got, want)
	}
}
