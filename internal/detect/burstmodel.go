// Package detect reproduces, offline and without cgo, the obfuscated-TLS
// heuristic that nDPI uses to spot tunnelled traffic by the size distribution
// of the first four bursts.
//
// Why this exists: measuring whether our traffic is detectable used to mean
// cloning nDPI from github, patching src/lib/protocols/tls.c to print the
// distances, rebuilding, capturing a dump and running ndpiReader. That is half
// a day of work and it cannot run in CI. The model itself is small - three
// centroids, three 4x4 inverse covariance matrices, two guard rules - so it
// ports directly and becomes a test.
//
// Source of every constant below: nDPI 5.1.0, src/lib/protocols/tls.c,
// function check_set(). A verbatim copy is kept at .ref/tls/ndpi-tls.c in the
// research repository. The constants are copied byte for byte and are NOT
// recomputed or tidied - see the note on matrix asymmetry in modelTLS13.
//
// This package is NOT the authority on whether we are detectable. It is a
// reimplementation and it can drift from the original. ndpiReader stays the
// arbiter:
//
//	ndpiReader -i dump.pcap --cfg=tls,dpi.heuristics,0x07 -v 2
//
// A disagreement between this package and ndpiReader is a bug here, and it
// matters more than the measurement that exposed it.
//
// The upstream heuristic is based on Xue, Kallitsis, Houmansadr and Ensafi,
// "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes",
// USENIX Security '24. nDPI differs from the paper: Mahalanobis distance only
// (no chi-squared), 4-grams instead of 3-grams, always starting from the
// client-to-server direction.
package detect

import (
	"math"
)

// TLSInTLSOverheadPerPacket is the per-packet overhead of the outer tunnel that
// nDPI subtracts before comparing against the models. The value is empirical in
// the nDPI source; the paper quotes "typically 20 to 60 bytes".
const TLSInTLSOverheadPerPacket = 24

// MaxFirstBurstPackets is the guard from check_set: a ClientHello is not split
// into many fragments, usually one, two with a post-quantum key share. Above
// this the heuristic gives up and reports nothing.
//
// Relying on this guard to stay undetected is fragile: real browsers send one
// or two packets, so deliberately fragmenting into four is itself an anomaly
// for any other detector. Margin reports such a window as MarginClear, and
// callers that care should look at Distances instead.
const MaxFirstBurstPackets = 3

// MinFirstBurstBytesTLS13 is the false-positive guard on the TLS 1.3 model:
// upstream states no TLS 1.3 ClientHello smaller than this was observed.
const MinFirstBurstBytesTLS13 = 517

// RequiredMargin is the acceptance threshold for our own traffic.
//
// It is not "greater than zero" on purpose. Live Chrome in our own baseline
// (test-logs/detectability-baseline-2026-08-24.md) came within 3.038 of the
// TLS 1.3 centroid whose threshold is 3.0 - real browser traffic sits right up
// against the cutoff. A censor who raises the threshold to 3.5 to catch more
// tunnels pays almost nothing in false positives, and anything we ship that
// sits at 3.2 would start being caught by that one edit. A margin of 0.9, i.e.
// a distance of at least 3.9, survives the threshold being raised to 3.9.
//
// Our measured traffic before any countermeasure sat at 0.815 to 1.668, i.e. a
// margin of roughly -1.3 to -2.2.
const RequiredMargin = 0.9

// MarginClear is what Margin returns when no model can fire at all, because a
// guard rejected the window before any distance was compared.
const MarginClear = math.MaxFloat64

// Model is one of the three distributions check_set compares against.
type Model struct {
	// Name matches the comment naming it in the nDPI source.
	Name string
	// Centroid is the mean byte count of the four bursts.
	Centroid [4]float64
	// InvCov is the inverted covariance matrix, row-major.
	InvCov [4][4]float64
	// Threshold is the Mahalanobis distance below which the window is a hit.
	Threshold float64
	// MinFirstBurstBytes, when non-zero, is a false-positive guard: the model
	// is skipped entirely when bytes[0] is below it.
	MinFirstBurstBytes uint32
}

// modelTLS12 corresponds to "Model: TLS 1.2; Firefox; No session resumption/0rtt".
var modelTLS12 = Model{
	Name: "tls12",
	Centroid: [4]float64{
		212.883690341977, 4514.71195039459, 107.770762871101, 307.580232995115,
	},
	InvCov: [4][4]float64{
		{0.000292421113167604, 4.43677617831228e-07, -5.69966093492813e-05, -2.18124698406311e-06},
		{4.43677617831228e-07, 5.98954952745268e-07, -3.59798436724817e-07, 5.71638172955893e-07},
		{-5.69966093492813e-05, -3.59798436724817e-07, 0.00076893788148309, 2.22278496185964e-05},
		{-2.18124698406311e-06, 5.71638172955893e-07, 2.22278496185964e-05, 5.72770077086287e-05},
	},
	Threshold: 3.5,
}

// modelTLS13 corresponds to
// "Model: TLS 1.3; Firefox; No session resumption/0rtt; no PQ; ECH(-grease) enabled".
//
// Note the asymmetry between InvCov[0][3] and InvCov[3][0]: upstream writes
// 3.8862884355278E-08 in one place and 3.88628843552779E-08 in the other, so
// the matrix is not exactly symmetric. That is almost certainly a typo in nDPI,
// and it is reproduced here deliberately - the point of this package is to be
// the detector we actually face, not the one it meant to be. The difference is
// far below anything that changes a verdict.
var modelTLS13 = Model{
	Name: "tls13",
	Centroid: [4]float64{
		640.657378447541, 4649.30338356554, 448.408302530566, 1094.2013079329,
	},
	InvCov: [4][4]float64{
		{3.08030337925007e-05, 1.16179172096944e-07, 1.05356744968627e-07, 3.8862884355278e-08},
		{1.16179172096944e-07, 6.93179117519316e-07, 2.77413220880937e-08, -3.63723200682445e-09},
		{1.05356744968627e-07, 2.77413220880937e-08, 1.0260950589675e-06, -1.08769813590053e-08},
		{3.88628843552779e-08, -3.63723200682445e-09, -1.08769813590053e-08, 8.63307792288604e-08},
	},
	Threshold:          3.0,
	MinFirstBurstBytes: MinFirstBurstBytesTLS13,
}

// modelChrome corresponds to
// "Model: TLS 1.2/1.3; Chrome; No session resumption/0rtt; PQ; ECH(-grease) enabled".
var modelChrome = Model{
	Name: "chrome",
	Centroid: [4]float64{
		1850.43045387994, 4903.07735480722, 785.25280624695, 1051.22303562714,
	},
	InvCov: [4][4]float64{
		{6.72374390966642e-06, -2.32109583941723e-08, 6.67140014394388e-08, 1.2526322628285e-08},
		{-2.32109583941723e-08, 5.64668947932086e-07, 4.58963631972597e-08, 6.41254684791958e-09},
		{6.67140014394388e-08, 4.58963631972597e-08, 6.04057768431344e-07, -9.1507432597718e-10},
		{1.2526322628285e-08, 6.41254684791958e-09, -9.1507432597718e-10, 1.01184796635481e-07},
	},
	Threshold: 3.0,
}

// Models are the three models in the order check_set evaluates them.
func Models() []Model {
	return []Model{modelChrome, modelTLS13, modelTLS12}
}

// Mahalanobis returns sqrt((x-mu)' * InvCov * (x-mu)).
func (m Model) Mahalanobis(bytes [4]uint32) float64 {
	var diff [4]float64
	for i := range diff {
		diff[i] = float64(bytes[i]) - m.Centroid[i]
	}

	var sum float64
	for i := range diff {
		var row float64
		for j := range diff {
			row += m.InvCov[i][j] * diff[j]
		}
		sum += diff[i] * row
	}
	if sum <= 0 {
		// Numerically possible for a point sitting on the centroid.
		return 0
	}
	return math.Sqrt(sum)
}

// applies reports whether the model is allowed to fire on this window, i.e.
// whether its own false-positive guard lets it through.
func (m Model) applies(bytes [4]uint32) bool {
	return m.MinFirstBurstBytes == 0 || bytes[0] >= m.MinFirstBurstBytes
}

// Burst is a flight: consecutive packets travelling in the same direction.
type Burst struct {
	// ToServer is the direction. nDPI always starts a window on a
	// client-to-server burst.
	ToServer bool
	// Bytes is the payload total, already net of TLSInTLSOverheadPerPacket
	// when the bursts came from BurstsFromPackets with subtraction enabled.
	Bytes uint32
	// Pkts is how many packets made up the burst.
	Pkts uint32
}

// Window is the 4-gram check_set scores.
type Window [4]Burst

// Bytes projects the window onto the vector the models compare against.
func (w Window) Bytes() [4]uint32 {
	return [4]uint32{w[0].Bytes, w[1].Bytes, w[2].Bytes, w[3].Bytes}
}

// Mode is which of the two branches inside tls_obfuscated_heur_search a flow
// takes. The branch is chosen by one local variable:
//
//	is_tls_in_tls_heur = flow->extra_packets_func &&
//	    (detected_protocol_stack[0] == TLS || detected_protocol_stack[1] == TLS)
//
// and in practice the protocol stack is decided by the PORT. A flow on 995 is
// subclassified as POPS, so TLS is not in the stack and the branch is Plain; a
// flow on a port that resolves to TLS takes the TLSInTLS branch. Nothing about
// what we put on the wire selects this - the port does.
//
// The two branches behave differently in two ways that both change the numbers,
// so a model that ignores the mode answers the wrong question.
type Mode int

const (
	// ModePlain: no ChangeCipherSpec gate, no per-packet overhead. Counting
	// starts at the first payload-carrying packet.
	ModePlain Mode = iota

	// ModeTLSInTLS: packets are ignored until a ChangeCipherSpec has been seen
	// in that direction, and TLSInTLSOverheadPerPacket is deducted per packet
	// to discount the outer tunnel's framing.
	ModeTLSInTLS
)

// Packet is one TCP segment. Zero-length segments (pure ACKs) are kept in the
// slice and skipped during the walk, matching the original, which returns early
// on payload_packet_len == 0 without touching any counter.
type Packet struct {
	ToServer   bool
	PayloadLen uint32
	// FirstByte is the first byte of the TCP payload, or 0 for an empty
	// segment. The heuristic's own gate tests exactly this: payload[0] == 0x14.
	FirstByte byte
}

// Flow is one TCP connection as the heuristic sees it.
type Flow struct {
	Packets []Packet
	Mode    Mode

	// CCSFromClient and CCSFromServer say whether the main TLS dissector had
	// already recorded a well-formed ChangeCipherSpec record in that direction
	// before the heuristic ran.
	//
	// There are two independent places that set these flags in nDPI, and only
	// modelling one of them gives wrong answers:
	//
	//   - the main dissector, on a reassembled record with content_type 0x14,
	//     length 6, version byte 0x03 and a length field of 1. That is a real
	//     CCS record, found by parsing, not by looking at a segment boundary.
	//   - the heuristic's own gate, on payload[0] == 0x14 of a segment. Cruder,
	//     and it is what the walk below implements.
	//
	// Reassembly is left to whoever produced the packets - tshark does it
	// properly - so the first path arrives here as these two booleans.
	CCSFromClient bool
	CCSFromServer bool

	// MaxPackets mirrors cfg.tls_heuristics_max_packets: once more than this
	// many payload-carrying packets have been examined the heuristic gives up.
	// Zero means no limit.
	//
	// The upstream default was not determined during our measurements, so a
	// zero here is "we do not know", not "there is no limit in nDPI".
	MaxPackets int
}

// Bursts walks the flow the way tls_obfuscated_heur_search does and returns the
// bursts that the models are scored against.
//
// excluded reports that the heuristic bailed out on this flow entirely, which
// is not the same as "scored and found clean": an excluded flow produces no
// verdict at all.
func (f Flow) Bursts() (bursts []Burst, excluded bool) {
	overhead := uint32(0)
	if f.Mode == ModeTLSInTLS {
		overhead = TLSInTLSOverheadPerPacket
	}

	ccsClient, ccsServer := f.CCSFromClient, f.CCSFromServer
	examined := 0

	for _, p := range f.Packets {
		if p.PayloadLen == 0 {
			continue
		}

		if f.Mode == ModeTLSInTLS {
			// A segment shorter than the overhead we are about to deduct stops
			// the heuristic outright rather than being skipped.
			if p.PayloadLen < overhead {
				return bursts, true
			}
			// The gate. Note that the packet which sets the flag is itself
			// skipped: the original sets the flag and then returns, so counting
			// begins on the next packet in that direction.
			if p.ToServer && !ccsClient {
				if p.FirstByte == 0x14 {
					ccsClient = true
				}
				continue
			}
			if !p.ToServer && !ccsServer {
				if p.FirstByte == 0x14 {
					ccsServer = true
				}
				continue
			}
		}

		examined++
		if f.MaxPackets > 0 && examined > f.MaxPackets {
			return bursts, true
		}

		if n := len(bursts); n > 0 && bursts[n-1].ToServer == p.ToServer {
			bursts[n-1].Bytes += p.PayloadLen
			bursts[n-1].Pkts++
			continue
		}
		bursts = append(bursts, Burst{ToServer: p.ToServer, Bytes: p.PayloadLen, Pkts: 1})
	}

	// The deduction is a property of the mode, never a caller's choice: tying
	// it to an argument is how the first version of this package grew a bug
	// that its tests could not see, because they fed vectors and never a flow.
	if overhead > 0 {
		for i := range bursts {
			d := bursts[i].Pkts * overhead
			if d >= bursts[i].Bytes {
				bursts[i].Bytes = 0
				continue
			}
			bursts[i].Bytes -= d
		}
	}
	return bursts, false
}

// Merge collapses consecutive same-direction bursts. Callers that assembled
// bursts by hand should run this first: check_set's notion of a burst is
// "consecutive packets in the same direction", so two adjacent same-direction
// entries are one burst, and scoring them separately silently models a
// detector that does not exist.
func Merge(bursts []Burst) []Burst {
	var out []Burst
	for _, b := range bursts {
		if n := len(out); n > 0 && out[n-1].ToServer == b.ToServer {
			out[n-1].Bytes += b.Bytes
			out[n-1].Pkts += b.Pkts
			continue
		}
		out = append(out, b)
	}
	return out
}

// Windows returns every 4-gram that starts on a client-to-server burst.
//
// Upstream keeps at most two sets alive at a time and closes the oldest when a
// new client-to-server flight begins, so it does not literally score every
// window. Returning all of them is deliberately stricter than the original: a
// countermeasure that clears every window clears the real detector too, whereas
// one tuned to the two-set bookkeeping would be betting on an implementation
// detail.
//
// The input must already be merged; call Merge if unsure.
func Windows(bursts []Burst) []Window {
	var out []Window
	for i := 0; i+4 <= len(bursts); i++ {
		if !bursts[i].ToServer {
			continue
		}
		out = append(out, Window(bursts[i:i+4]))
	}
	return out
}

// Distances returns the raw Mahalanobis distance to each model, ignoring every
// guard. Useful for reporting and for understanding why a window scored the way
// it did; Caught is what decides.
func Distances(w Window) map[string]float64 {
	b := w.Bytes()
	out := make(map[string]float64, 3)
	for _, m := range Models() {
		out[m.Name] = m.Mahalanobis(b)
	}
	return out
}

// Caught reproduces check_set: true means nDPI flags the flow as obfuscated.
// The second return value names the model that fired, empty when none did.
func Caught(w Window) (bool, string) {
	if w[0].Pkts > MaxFirstBurstPackets {
		return false, ""
	}
	b := w.Bytes()
	for _, m := range Models() {
		if !m.applies(b) {
			continue
		}
		if m.Mahalanobis(b) < m.Threshold {
			return true, m.Name
		}
	}
	return false, ""
}

// Margin is how much room the window has before it is caught: the smallest
// distance-minus-threshold across every model that is allowed to fire. Positive
// means clear, and RequiredMargin is the number we hold ourselves to.
//
// A window rejected by the packet-count guard returns MarginClear. That is
// faithful to the detector but a poor thing to rely on - see the note on
// MaxFirstBurstPackets.
func Margin(w Window) float64 {
	if w[0].Pkts > MaxFirstBurstPackets {
		return MarginClear
	}
	b := w.Bytes()
	worst := MarginClear
	for _, m := range Models() {
		if !m.applies(b) {
			continue
		}
		worst = min(worst, m.Mahalanobis(b)-m.Threshold)
	}
	return worst
}

// Worst returns the window with the least margin across a whole flow, which is
// the number that decides whether the flow is safe: one bad window is enough
// for a censor.
//
// ok is false when the flow has no window starting client-to-server, i.e. there
// is nothing for the heuristic to score.
func Worst(bursts []Burst) (w Window, margin float64, ok bool) {
	margin = MarginClear
	for _, cand := range Windows(Merge(bursts)) {
		if m := Margin(cand); m < margin {
			w, margin, ok = cand, m, true
		}
	}
	// A flow whose every window is guard-cleared still has windows; report the
	// first so callers have something to print.
	if !ok {
		if all := Windows(Merge(bursts)); len(all) > 0 {
			return all[0], MarginClear, true
		}
	}
	return w, margin, ok
}
