package detect

// Which of the two paths through nDPI's obfuscated-TLS heuristic a flow takes,
// and why it matters more than it looks.
//
// tls_obfuscated_heur_search() behaves in two completely different ways
// depending on one local variable:
//
//	if(flow->extra_packets_func &&
//	   (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS ||
//	    flow->detected_protocol_stack[1] == NDPI_PROTOCOL_TLS))
//	  is_tls_in_tls_heur = 1;
//
// With it set, nDPI subtracts 24 bytes per packet and refuses to count anything
// until it has seen a record starting with 0x14 - a ChangeCipherSpec - in each
// direction. With it clear, nothing is subtracted and counting starts on the
// first packet with a payload.
//
// Which branch we land on is decided by the listening port, not by anything we
// do on the wire. Measured on 2026-08-25 by instrumenting nDPI 5.1.0 and
// re-running both dumps:
//
//	test-logs/detect-baseline/ours-reality-dubai.pcap   port 995
//	    is_tls_in_tls=0 overhead=0
//	    protocol stack: [Yandex|Github|GithubActions, POPS] - no TLS in it,
//	    because port 995 makes POPS the master protocol
//	    -> counting starts on the first data packet, nothing subtracted
//
//	test-logs/reshape-e2e/reshape-off.pcap              port 19443
//	    is_tls_in_tls=1 overhead=24
//	    protocol stack: [Github|GithubActions, TLS]
//	    -> waits for a 0x14 in each direction, which our framing never sends
//	       (internal/strategy/reality_conn.go writes 0x17 only and the reader
//	       rejects anything else), so it never counts a single packet
//
// Two consequences that are easy to get backwards:
//
//  1. The baseline four-grams - 530/2833/281/588 and the rest - are RAW wire
//     byte counts. Nothing was subtracted from them. Earlier write-ups
//     described them as net of the 24-byte overhead; that was wrong, and
//     feeding them through BurstsFromPackets with subtraction on would shrink
//     every burst by 24 per packet and produce margins for a detector that was
//     not the one that caught us.
//
//  2. bytes[0] = 530 on all twelve caught flows is not a coincidence and not a
//     random starting point. On the plain path counting begins at the first
//     data packet, and the first client record after the dispatch byte is the
//     tunnelled ClientHello. Twelve flows agreeing is exactly what that path
//     predicts.
//
// A third, operational one: on port 995 we are on the path with no start
// condition at all. Moving to a port where nDPI keeps TLS in the protocol stack
// puts us on the path that never starts, because we never send a 0x14 - but
// that silence is itself signal number one from the improvement plan, and B1
// will introduce a real ChangeCipherSpec, which is precisely what the gate is
// waiting for.

// Mode selects which of the two paths to reproduce.
type Mode int

const (
	// ModePlain is the path our production flows actually take: no overhead
	// subtraction, no start condition, counting from the first packet.
	ModePlain Mode = iota

	// ModeTLSInTLS is the path taken when nDPI keeps TLS in the protocol stack:
	// 24 bytes subtracted per packet, and nothing is counted until a record
	// starting with 0x14 has been seen in each direction.
	ModeTLSInTLS
)

func (m Mode) String() string {
	if m == ModeTLSInTLS {
		return "tls-in-tls"
	}
	return "plain"
}

// changeCipherSpec is the record type the TLS-in-TLS path waits for. nDPI looks
// at the first byte of the TCP payload, so a record boundary landing anywhere
// else in the segment does not count.
const changeCipherSpec = 0x14

// WirePacket is a packet as it appeared on the wire, with the first payload
// byte kept because the TLS-in-TLS start condition is expressed in terms of it.
type WirePacket struct {
	ToServer   bool
	PayloadLen uint32
	FirstByte  byte
}

// Analyze turns a packet sequence into the windows the real detector would
// score, reproducing the start condition and the overhead rule of the given
// mode. Use this rather than BurstsFromPackets when the answer has to match
// ndpiReader: BurstsFromPackets knows about the overhead but not about the
// start condition, so on the TLS-in-TLS path it reports windows that the
// original would never evaluate.
//
// scored reports whether the detector ended up scoring this flow at all. False
// covers both ways the TLS-in-TLS path gives up: the start condition never
// being met, and the flow being excluded outright by a packet shorter than the
// overhead - our one-byte dispatch does exactly that, so on this path the flow
// is dropped even when a ChangeCipherSpec has been seen.
func Analyze(pkts []WirePacket, mode Mode) (windows []Window, scored bool) {
	counted := make([]Packet, 0, len(pkts))

	if mode == ModeTLSInTLS {
		var sawClient, sawServer bool
		for _, p := range pkts {
			if p.PayloadLen == 0 {
				continue
			}
			// Mirror the original's ordering: the direction's flag is checked
			// first, and the packet that carries the 0x14 is itself skipped.
			if p.ToServer && !sawClient {
				if p.FirstByte == changeCipherSpec {
					sawClient = true
				}
				continue
			}
			if !p.ToServer && !sawServer {
				if p.FirstByte == changeCipherSpec {
					sawServer = true
				}
				continue
			}
			if uint32(TLSInTLSOverheadPerPacket) > p.PayloadLen {
				// "packet too small. Stop." - the original returns Exclude,
				// which drops the flow entirely rather than scoring what it
				// has so far.
				return nil, false
			}
			counted = append(counted, Packet{ToServer: p.ToServer, PayloadLen: p.PayloadLen})
		}
		if !sawClient || !sawServer || len(counted) == 0 {
			return nil, false
		}
		windows = Windows(Merge(BurstsFromPackets(counted, true)))
		return windows, len(windows) > 0
	}

	for _, p := range pkts {
		if p.PayloadLen == 0 {
			continue
		}
		counted = append(counted, Packet{ToServer: p.ToServer, PayloadLen: p.PayloadLen})
	}
	if len(counted) == 0 {
		return nil, false
	}
	windows = Windows(Merge(BurstsFromPackets(counted, false)))
	return windows, len(windows) > 0
}
