package client

import (
	"net"
	"strings"
	"testing"
)

// fakeTunnel stands in for *tun.VPNClient and records whether it was asked for
// the address at all, so a version that prints something else without consulting
// the tunnel is caught even if the string happens to look right.
type fakeTunnel struct {
	ip    net.IP
	asked bool
}

func (f *fakeTunnel) LocalIP() net.IP {
	f.asked = true
	return f.ip
}

// TestLogVPNStartedPrintsAssignedNotRequested is the regression guard for the
// defect itself: the line must carry the address the interface ended up with,
// while the requested one sits right there in cfg, reachable and wrong.
//
// The addresses are the ones from the log that caused the trouble: the client
// asked for 10.8.0.2, the exit assigned 10.8.5.3, and the old line printed the
// request - which was then read as two clients colliding on one address.
func TestLogVPNStartedPrintsAssignedNotRequested(t *testing.T) {
	buf := captureLog(t)

	cfg := &Config{TunName: "tiredvpn-usa2", TunIP: "10.8.0.2"}
	tunnel := &fakeTunnel{ip: net.IPv4(10, 8, 5, 3)}

	logVPNStarted(cfg, tunnel)

	out := buf.String()
	if !tunnel.asked {
		t.Error("the line was produced without asking the tunnel for its address")
	}
	if !strings.Contains(out, "10.8.5.3") {
		t.Errorf("assigned address missing from the line: %q", out)
	}
	if strings.Contains(out, "10.8.0.2") {
		t.Errorf("line carries the requested address instead of the assigned one - this is the defect: %q", out)
	}
	if !strings.Contains(out, "tiredvpn-usa2") {
		t.Errorf("interface name missing from the line: %q", out)
	}
}

// TestLogVPNStartedWhenExitEchoedTheRequest: when the exit hands back the
// address that was asked for, the line is the same either way. The value must
// still come from the tunnel - otherwise the test above passes for the wrong
// reason on any exit with a sticky assignment.
func TestLogVPNStartedWhenExitEchoedTheRequest(t *testing.T) {
	buf := captureLog(t)

	cfg := &Config{TunName: "tiredvpn0", TunIP: "10.8.0.2"}
	tunnel := &fakeTunnel{ip: net.IPv4(10, 8, 0, 2)}

	logVPNStarted(cfg, tunnel)

	if !tunnel.asked {
		t.Error("the line was produced without asking the tunnel for its address")
	}
	if out := buf.String(); !strings.Contains(out, "10.8.0.2") {
		t.Errorf("address missing from the line: %q", out)
	}
}

// TestLogVPNStartedNamesTheInterfaceNotTheAddress guards the other half of the
// format: two %s in one line are easy to transpose, and a transposed line reads
// plausibly enough to survive review.
func TestLogVPNStartedNamesTheInterfaceNotTheAddress(t *testing.T) {
	buf := captureLog(t)

	cfg := &Config{TunName: "tiredvpn-usa2", TunIP: "10.8.0.2"}
	logVPNStarted(cfg, &fakeTunnel{ip: net.IPv4(10, 8, 5, 3)})

	out := buf.String()
	nameAt := strings.Index(out, "tiredvpn-usa2")
	ipAt := strings.Index(out, "10.8.5.3")
	if nameAt < 0 || ipAt < 0 {
		t.Fatalf("line is missing the name or the address: %q", out)
	}
	if nameAt > ipAt {
		t.Errorf("address printed where the interface name belongs: %q", out)
	}
}
