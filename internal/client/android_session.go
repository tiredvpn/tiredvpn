package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// androidSessionUsefulMin is how long a relay's session must have lived for
// its end to say nothing against the strategy - the desktop's
// sessionUsefulMin. The relay knows its lifetime, not its downlink clock.
const androidSessionUsefulMin = 20 * time.Second

// androidSession is the session the control socket's relay carries: which
// strategy and endpoint it rode, so that its end is booked against them.
// Without it the storm detector never saw an Android session start, and a
// stall verdict was charged to whatever the pin was by then.
type androidSession struct {
	mgr *strategy.Manager
	// linkUp is asked before an endpoint is charged; tun.LocalLinkUp when nil.
	linkUp func() bool

	mu      sync.Mutex
	strat   string
	cand    endpoint.Candidate
	hasCand bool

	// stopped is set when the host takes the tunnel down on purpose (the
	// user's stop): what this core learned is not handed to the next one.
	stopped atomic.Bool
}

// started records a session that came up on s at cand.
func (a *androidSession) started(s strategy.Strategy, cand endpoint.Candidate, hasCand bool) {
	if s == nil {
		return
	}
	a.mu.Lock()
	a.strat, a.cand, a.hasCand = s.ID(), cand, hasCand
	a.mu.Unlock()
	a.mgr.RecordSessionStart(s.ID())
}

// ended books the end of the session the relay carried: once per start.
// A degraded one parks its endpoint like a dead session and has the next
// connect walk the pool; any other end feeds the strategy's confidence and
// the storm detector as on the desktop. A silent death is not charged to the
// endpoint here (the relay can not tell its downlink age).
func (a *androidSession) ended(end tun.RelaySessionEnd) {
	a.mu.Lock()
	id, cand, hasCand := a.strat, a.cand, a.hasCand
	a.strat = ""
	a.mu.Unlock()
	if id == "" {
		return
	}
	if end.Degraded {
		a.mgr.NoteServerSilent()
	}
	a.mgr.SessionEnded(strategy.SessionEnd{
		Strategy:       id,
		Endpoint:       cand,
		HasEndpoint:    hasCand,
		Useful:         !end.Degraded && end.Lifetime >= androidSessionUsefulMin,
		Degraded:       end.Degraded,
		LocalNetworkUp: a.localLinkUp,
	})
}

func (a *androidSession) localLinkUp() bool {
	if a.linkUp != nil {
		return a.linkUp()
	}
	return tun.LocalLinkUp()
}

// androidControlConfig is the control server's configuration for cfg: how it
// connects, reconnects and books the sessions it carries on mgr.
func androidControlConfig(cfg *Config, mgr *strategy.Manager, dualStack bool, sess *androidSession) *tun.ControlConfig {
	return &tun.ControlConfig{
		ServerAddr: cfg.ServerAddr,
		Secret:     cfg.Secret,
		MTU:        cfg.TunMTU,
		DNS:        "8.8.8.8", // Default DNS
		Routes:     cfg.TunRoutes,
		DualStack:  dualStack,

		// ReconnectFn - a network change (WiFi→LTE, cell handoff) or the
		// relay's auto-reconnect. Must send TUN handshake with current IP
		// so server knows this is a TUN session.
		ReconnectFn: func(ctx context.Context, currentIP net.IP, mtu int, networkChanged bool) (tun.ReconnectResult, error) {
			res, r, err := reconnectTUN(ctx, mgr, cfg.ServerAddr, currentIP, mtu, dualStack, networkChanged)
			if err == nil {
				sess.started(r.strat, r.cand, r.hasCand)
			}
			return res, err
		},

		// Connect function - connects to server, returns assigned IP
		ConnectFn: func(ctx context.Context) (assignedIP, serverIP net.IP, conn net.Conn, err error) {
			serverConn, strat, cand, hasCand, err := mgr.ConnectSession(ctx, cfg.ServerAddr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to connect: %w", err)
			}
			sess.started(strat, cand, hasCand)

			log.Info("Connected via %s, waiting for TUN fd from Android", strat.Name())

			// Return connection WITHOUT TUN handshake
			// TUN handshake will be done AFTER Android creates VPN interface and sends FD
			// This fixes the "handshake read failed: EOF" error
			// Use placeholder IPs (10.9.0.2/10.9.0.1) - real IPs will be set after handshake
			// NOTE: 0.0.0.0 causes Android to fail VPN interface creation
			placeholderClient := net.IPv4(10, 9, 0, 2)
			placeholderServer := net.IPv4(10, 9, 0, 1)
			return placeholderClient, placeholderServer, serverConn, nil
		},

		// GetConnectionInfoFn returns connection metadata for Android UI
		GetConnectionInfoFn: func() tun.ConnectionMetadata {
			info := mgr.GetLastConnectionInfo()
			return tun.ConnectionMetadata{
				Strategy:  info.Strategy,
				LatencyMs: info.Latency.Milliseconds(),
				Attempts:  info.Attempts,
			}
		},

		// SessionEndedFn books the relay's session end against the strategy
		// and endpoint it rode, as VPNClient's disconnect does on the desktop.
		SessionEndedFn: sess.ended,

		// DisconnectedFn: the user stopped the tunnel. The next start is a
		// fresh one, perhaps on another network: no carry (carryFrom).
		DisconnectedFn: func() { sess.stopped.Store(true) },

		// StartVPNFn is NOT set - let control.go use the default path
		// which includes RunTUNRelayWithCallbacks with keepalive events
		// and dead connection detection
	}
}

// androidCarry is what one core's manager learned that the next core's
// starts with. The app restarts the whole core on every dead connection
// (connection_dead, then stopClient and startClient in the same process),
// and every start builds a new manager: a server parked for a degraded
// session a moment before was forgotten, the storm detector never saw two
// sessions, and the route rule never saw a death on the previous server -
// so on Android the client walked every exit on a transport the route had
// killed (P1-4 of the round-5 review). Endpoint health is matched by
// address, so a core over a different pool takes over nothing of it.
//
// It is for that restart only. A carry older than androidCarryTTL is
// dropped, and a core the user stopped leaves none: either may have been
// followed by a move to another network, which the next core cannot see.
var androidCarry struct {
	mu     sync.Mutex
	health []endpoint.HealthRecord
	storm  *strategy.StormDetector
	route  strategy.RouteMemory
	at     time.Time
}

// androidCarryTTL is how long a carry waits for the next core. The app
// restarts the core within seconds of a dead connection; its reconnect
// backoff stays well under this.
const androidCarryTTL = 2 * time.Minute

// carryInto hands mgr what the previous core learned. Call before connecting.
func carryInto(mgr *strategy.Manager) {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	if androidCarry.at.IsZero() {
		return
	}
	if age := time.Since(androidCarry.at); age > androidCarryTTL {
		log.Info("Not taking over the previous core's server verdicts: %v old", age.Round(time.Second))
		return
	}
	mgr.ImportEndpointHealth(androidCarry.health)
	mgr.AdoptStormHistory(androidCarry.storm)
	mgr.AdoptRouteHistory(androidCarry.route)
}

// carryFrom keeps what mgr learned for the next core, unless sess was
// stopped by the user: then it clears the carry.
func carryFrom(mgr *strategy.Manager, sess *androidSession) {
	androidCarry.mu.Lock()
	defer androidCarry.mu.Unlock()
	if sess != nil && sess.stopped.Load() {
		androidCarry.health, androidCarry.storm = nil, nil
		androidCarry.route, androidCarry.at = strategy.RouteMemory{}, time.Time{}
		return
	}
	androidCarry.health = mgr.EndpointHealth()
	androidCarry.storm = mgr.StormHistory()
	androidCarry.route = mgr.RouteHistory()
	androidCarry.at = time.Now()
}
