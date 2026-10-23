package tun

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// autoReconnectArgs runs doAutoReconnect until its first ReconnectFn call and
// returns the networkChanged it was given. netUp answers the network checks.
func autoReconnectArgs(t *testing.T, netUp func() bool) bool {
	t.Helper()
	setLog(t, &stampedLog{})
	got := make(chan bool, 1)
	stop := make(chan struct{})
	cs := &ControlServer{
		config: &ControlConfig{ReconnectFn: func(_ context.Context, _ net.IP, _ int, networkChanged bool) (ReconnectResult, error) {
			select {
			case got <- networkChanged:
			default:
			}
			return ReconnectResult{}, errors.New("test exit refuses")
		}},
		tunDev:               &TUNDevice{},
		tunFd:                5,
		autoReconnectStop:    stop,
		networkAvailableChan: make(chan struct{}, 1),
		netCheck:             netUp,
	}
	done := make(chan struct{})
	go func() { cs.doAutoReconnect("server_read: EOF"); close(done) }()
	defer func() { close(stop); <-done }()
	select {
	case v := <-got:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("ReconnectFn never called")
		return false
	}
}

// TestRelayDeathOnTheSameNetworkKeepsWhatWasLearned is the control-socket
// half of P1-2 of the round-4 review: the relay's auto-reconnect went
// through the network-change reset, which wiped the park a degraded verdict
// had just set. A relay that died on a network that is still up reconnects
// as on the same network; one that had to wait for the network does not.
func TestRelayDeathOnTheSameNetworkKeepsWhatWasLearned(t *testing.T) {
	if autoReconnectArgs(t, func() bool { return true }) {
		t.Fatal("a relay death on a working network was reconnected as a network change")
	}
	calls := 0
	if !autoReconnectArgs(t, func() bool { calls++; return calls > 1 }) {
		t.Fatal("a reconnect after waiting for the network was not treated as a network change")
	}
}
