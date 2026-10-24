package client

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// TestACarryIsStampedWithTheNetworkItWasLearnedOn is P3-1 of the round-8
// review, through two real cores: the host names the new network on
// "network_changed" before the core resets for it, and a reconnect that
// ended first ("VPN not active" here) left the old network's verdicts
// stamped with the new network. The next core, on the new network, took
// them over and avoided the server they parked.
func TestACarryIsStampedWithTheNetworkItWasLearnedOn(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
		if got := connectOn(t, sock, "100", &dials, &mu); got != "reality@"+pool[0] {
			t.Fatalf("the first core dialled %s", got)
		}
		ctl.SessionEndedFn(degraded)
		if resp := answerOf(t, sock, `{"command":"network_changed","network_id":"101"}`); !strings.Contains(resp, "VPN not active") {
			t.Fatalf("network_changed answered %s, want it to end before the reset - the test proves nothing", resp)
		}
	})
	var got string
	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		got = connectOn(t, sock, "101", &dials, &mu)
	})
	if got != "reality@"+pool[0] {
		t.Fatalf("the core on network 101 dialled %s: it took over network 100's verdicts", got)
	}
}

// answerOf sends cmd and returns its answer, past the events the core sends
// ahead of it.
func answerOf(t *testing.T, sock, cmd string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(cmd)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(c)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("%s: no answer: %v", cmd, err)
		}
		if _, ok := m["status"]; ok {
			b, _ := json.Marshal(m)
			return string(b)
		}
	}
}

// TestACarryLearnedAfterANetworkChangeIsTheNewNetworks: the other half of
// P3-1. Once the core has reset for the new network, what it learns there is
// the new network's, and the next core on it takes it over.
func TestACarryLearnedAfterANetworkChangeIsTheNewNetworks(t *testing.T) {
	pool := fourExitPool(t)
	t.Cleanup(clearCarry)
	var dials []string
	var mu sync.Mutex
	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, ctl *tun.ControlConfig) {
		if got := connectOn(t, sock, "100", &dials, &mu); got != "reality@"+pool[0] {
			t.Fatalf("the first core dialled %s", got)
		}
		answerOf(t, sock, `{"command":"status","network_id":"101"}`)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := ctl.ReconnectFn(ctx, reconnClientIP, 1280, true)
		if err != nil {
			t.Fatalf("the network-change reconnect: %v", err)
		}
		res.Conn.Close()
		ctl.SessionEndedFn(degraded) // learned on 101
	})
	var got string
	runCore(t, coreOn(t, pool, &dials, &mu), pool, os.Interrupt, func(sock string, _ *tun.ControlConfig) {
		got = connectOn(t, sock, "101", &dials, &mu)
	})
	if got == "reality@"+pool[0] {
		t.Fatalf("the core on network 101 dialled %s: it dropped what was learned on 101", got)
	}
}
