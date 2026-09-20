//go:build linux

package strategy

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"

	"github.com/tiredvpn/tiredvpn/internal/capabilities"
	"github.com/tiredvpn/tiredvpn/internal/geneva"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// seqovlQueueNum is the NFQUEUE number the level-A overlap injector attaches to.
// Distinct from Geneva's queue 0 so the two can coexist. The operator must add a
// matching OUTPUT rule, e.g.:
//
//	iptables -I OUTPUT -p tcp -d <server-ip> --dport <port> \
//	    -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num 1
const seqovlQueueNum = 1

// tryStartPacketOverlap brings up the packet-level seqovl injector once, if the
// host has CAP_NET_ADMIN. It is best-effort: without CAP_NET_ADMIN (or without
// the operator's OUTPUT NFQUEUE rule) it simply does nothing and the connection
// rides the level-B app-framing decoy alone. Returns true when the injector is
// active.
//
// The default OverlapPrimitive uses the safe geometry (fake segment sits below
// the server's rcv_nxt), so even without the server-side NFQUEUE drop the
// cooperating server's kernel discards the fake and the real stream stays clean.
//
// secret is the key of the endpoint being dialled, and it keys the per-connection
// markers. One NFQUEUE hook serves the whole process, and the marker's *secret*
// is captured from the endpoint that started the injector - so the injector is
// still pinned to that endpoint's key, and a later endpoint with a different key
// gets a warning rather than a second injector. The *nonce*, however, is now
// minted fresh per connection by the OverlapPrimitive, so the fake segments are
// no longer one fixed 32-byte value across the process; see SeqovlStrategy.
func (s *SeqovlStrategy) tryStartPacketOverlap(secret []byte) bool {
	if !s.packetEnabled {
		return false
	}
	caps := capabilities.Probe()
	if !caps.HasNetAdmin {
		log.Debug("Seqovl: packet-level overlap requested but CAP_NET_ADMIN missing (%s) - staying on level B", caps)
		return false
	}

	s.injectorOnce.Do(func() {
		// Mint a fresh nonce (hence a fresh marker) for each connection's fake
		// segment. The injector is one process-wide NFQUEUE hook, but the
		// OverlapPrimitive calls this per connection, so the [nonce||HMAC] marker
		// is not the same 32 bytes on every fake segment (see seqovlPacketMarker).
		secretCopy := append([]byte(nil), secret...)
		mint := func() []byte {
			nonce := make([]byte, seqovlPacketNonceLen)
			if _, err := cryptorand.Read(nonce); err != nil {
				log.Debug("Seqovl: packet-level nonce generation failed: %v - fake suppressed for this connection", err)
				return nil
			}
			return seqovlPacketMarker(secretCopy, nonce)
		}
		prim := geneva.NewOverlapPrimitiveMinted(mint)
		strat := geneva.NewOverlapStrategy(prim)

		ctx, cancel := context.WithCancel(context.Background())
		inj := geneva.NewInjector(seqovlQueueNum, []*geneva.Strategy{strat})
		if err := inj.Start(ctx); err != nil {
			cancel()
			log.Debug("Seqovl: packet-level injector failed to start: %v - staying on level B", err)
			return
		}
		s.injector = inj
		s.injectorStop = cancel
		s.injectorSecret = append([]byte(nil), secret...)
		s.packetActive.Store(true)
		log.Info("Seqovl: packet-level overlap active on NFQUEUE %d (server must provision the OUTPUT rule)", seqovlQueueNum)
	})

	if s.packetActive.Load() && !bytes.Equal(s.injectorSecret, secret) {
		s.mismatchOnce.Do(func() {
			log.Warn("Seqovl: packet-level overlap is marked with the key of the endpoint that started it " +
				"and cannot follow a switch; this endpoint rides the level-B decoy alone")
		})
	}
	return s.packetActive.Load()
}
