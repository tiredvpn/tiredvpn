package tun

import (
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The fixtures in testdata/stall are cut from the TUN captures of the
// 2026-10-22 stand run (test-logs/degraded-2026-10-22/runs/*/rec/tun-*.pcap,
// LINKTYPE_RAW, snaplen 96): real packets with their real timestamps.
//
//   - flows.pcap.gz: frames 1-30 and 2002 of runs/_partial - one IPv4 and one
//     IPv6 HTTP flow from SYN to FIN, and a RST.
//   - pol_inter.pcap.gz: HTTP Polling h_inter, 300 s of interactive load on a
//     healthy tunnel (the report's F.max 0.07 s).
//   - pol_slow256k.pcap.gz: HTTP Polling c_slow256k, an honestly slow link
//     with a download (F.max 19.6 s), thinned: the bare ACKs going up (never
//     demand) are dropped, and per flow a plain packet coming down is kept
//     only if the flow sent something since the last kept one or 200 ms have
//     passed - 3192 of 189026 packets; a flow's last answer moves by under
//     0.2 s at most.
//   - pol_bbc40k.pcap.gz: HTTP Polling b_bc40k, a 40 KB per-flow byte cap
//     with a download (FAULT at 1792709833.682, F>=30 at 32.0 s), thinned
//     the same way (2539 of 265603 packets).
//   - pol_bhdown.pcap.gz: HTTP Polling d_bhdown, the tunnel blackholed
//     downstream (FAULT at 1792709084.455, F>=30 at 30.7 s).

type capturedPacket struct {
	at   time.Time
	data []byte
}

func readStallFixture(t *testing.T, name string) []capturedPacket {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "stall", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var hdr [24]byte
	if _, err := io.ReadFull(zr, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(hdr[20:24]) != 101 {
		t.Fatalf("%s: not a little-endian LINKTYPE_RAW pcap", name)
	}
	var out []capturedPacket
	for {
		var rec [16]byte
		if _, err := io.ReadFull(zr, rec[:]); err != nil {
			break
		}
		incl := binary.LittleEndian.Uint32(rec[8:12])
		data := make([]byte, incl)
		if _, err := io.ReadFull(zr, data); err != nil {
			t.Fatalf("%s: truncated record", name)
		}
		at := time.Unix(int64(binary.LittleEndian.Uint32(rec[0:4])), int64(binary.LittleEndian.Uint32(rec[4:8]))*1000)
		out = append(out, capturedPacket{at: at, data: data})
	}
	if len(out) == 0 {
		t.Fatalf("%s: no packets", name)
	}
	return out
}

var (
	tunnelV4 = netip.MustParsePrefix("10.8.1.0/24")
	tunnelV6 = netip.MustParsePrefix("fd00:8:1::/64")
	serverV4 = netip.MustParseAddr("10.8.1.1")
	serverV6 = netip.MustParseAddr("fd00:8:1::1")
)

// cameDown reports whether the captured packet went from the tunnel into
// the TUN: addressed to the client's tunnel address.
func cameDown(pkt []byte) bool {
	var dst netip.Addr
	switch pkt[0] >> 4 {
	case 4:
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	case 6:
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
	default:
		return false
	}
	return (tunnelV4.Contains(dst) || tunnelV6.Contains(dst)) && dst != serverV4 && dst != serverV6
}

// replay feeds a capture through a flow table on the capture's own clock,
// checking once a second as the monitor does, and returns the longest stall
// seen and when it first reached the threshold (zero if never).
func replay(t *testing.T, pkts []capturedPacket) (maxStall time.Duration, crossed time.Time) {
	t.Helper()
	ft := newFlowTable()
	check := func(now time.Time) {
		s := ft.stalledFor(now)
		maxStall = max(maxStall, s)
		if s >= stallClocks().threshold && crossed.IsZero() {
			crossed = now
		}
	}
	every := stallClocks().checkEvery
	next := pkts[0].at.Truncate(every).Add(every)
	for _, p := range pkts {
		for ; next.Before(p.at); next = next.Add(every) {
			check(next)
		}
		if cameDown(p.data) {
			ft.down(p.data, p.at)
		} else {
			ft.up(p.data, p.at)
		}
	}
	check(pkts[len(pkts)-1].at)
	return maxStall, crossed
}

// TestStallOnTheStandCaptures is the positive and the negative control on
// the same tool (verification rule 2): the healthy and honestly slow phases
// stay far under the threshold, the two "nothing comes through" phases cross
// it about 30 s after the fault, as the stand's own feature extractor did.
func TestStallOnTheStandCaptures(t *testing.T) {
	for _, tc := range []struct {
		file  string
		fault int64 // FAULT from events.log, unix ms; zero: must never cross
		limit time.Duration
	}{
		{"pol_inter.pcap.gz", 0, time.Second},
		{"pol_slow256k.pcap.gz", 0, 21 * time.Second},
		{"pol_bbc40k.pcap.gz", 1792709833682, 0},
		{"pol_bhdown.pcap.gz", 1792709084455, 0},
	} {
		t.Run(tc.file, func(t *testing.T) {
			maxStall, crossed := replay(t, readStallFixture(t, tc.file))
			t.Logf("longest stall %v, crossed at %v", maxStall, crossed)
			if tc.fault == 0 {
				if !crossed.IsZero() || maxStall > tc.limit {
					t.Fatalf("a healthy phase stalled %v (crossed at %v)", maxStall, crossed)
				}
				return
			}
			fault := time.UnixMilli(tc.fault)
			if crossed.IsZero() {
				t.Fatalf("never crossed %v, longest stall %v", stallClocks().threshold, maxStall)
			}
			if after := crossed.Sub(fault); after < 29*time.Second || after > 34*time.Second {
				t.Fatalf("crossed %v after the fault, want about 30 s", after)
			}
		})
	}
}

// fixtureFlows returns the frames of flows.pcap.gz, in capture order.
func fixtureFlows(t *testing.T) []capturedPacket {
	t.Helper()
	pkts := readStallFixture(t, "flows.pcap.gz")
	if len(pkts) != 31 {
		t.Fatalf("flows.pcap.gz has %d frames, want 31", len(pkts))
	}
	return pkts
}

// TestParseTCPSegmentOnRealPackets reads the stand's own packets: IPv4 with
// TCP options, IPv6 cut short by the capture, a FIN without data, a RST.
func TestParseTCPSegmentOnRealPackets(t *testing.T) {
	pkts := fixtureFlows(t)
	for _, tc := range []struct {
		frame   int // 1-based, as in the source capture
		payload int
		fin     bool
		syn     bool
		rst     bool
		v6      bool
	}{
		{frame: 1, syn: true},             // SYN with options
		{frame: 4},                        // bare ACK
		{frame: 6, payload: 29},           // GET /id, timestamps option
		{frame: 8, payload: 29, v6: true}, // v6 GET, capture cut at 96 bytes
		{frame: 11, payload: 199},         // the answer coming down
		{frame: 13, payload: 6, fin: true},
		{frame: 16, fin: true}, // FIN without data
		{frame: 31, rst: true}, // frame 2002 of the source
	} {
		seg, ok := parseTCPSegment(pkts[tc.frame-1].data)
		if !ok {
			t.Fatalf("frame %d did not parse", tc.frame)
		}
		if seg.payload != tc.payload || seg.fin != tc.fin || seg.syn != tc.syn || seg.rst != tc.rst || seg.src.Addr().Is6() != tc.v6 {
			t.Errorf("frame %d: %+v", tc.frame, seg)
		}
	}
}

// TestIPv6ExtensionHeaderIsSkipped: the captures hold no IPv6 packet with an
// extension header, so one is made from the stand's v6 GET (frame 8) by
// setting its next header to hop-by-hop. It is skipped, not misread.
func TestIPv6ExtensionHeaderIsSkipped(t *testing.T) {
	pkt := append([]byte(nil), fixtureFlows(t)[7].data...)
	if _, ok := parseTCPSegment(pkt); !ok {
		t.Fatal("the unmodified frame does not parse - the test proves nothing")
	}
	pkt[6] = 0 // hop-by-hop options
	if _, ok := parseTCPSegment(pkt); ok {
		t.Fatal("an IPv6 packet with an extension header was read as TCP")
	}
	ft := newFlowTable()
	ft.up(pkt, time.Now())
	ft.down(pkt, time.Now())
	if len(ft.flows) != 0 {
		t.Fatal("a skipped packet created a flow")
	}
}

// TestFlowDemand runs the IPv4 flow of the fixture: the GET after the
// handshake is demand once the flow has been answered, the answer clears it,
// and the FIN without data is demand again.
func TestFlowDemand(t *testing.T) {
	pkts := fixtureFlows(t)
	ft := newFlowTable()
	at := func(f int) time.Time { return pkts[f-1].at }
	feed := func(f int) {
		if cameDown(pkts[f-1].data) {
			ft.down(pkts[f-1].data, at(f))
		} else {
			ft.up(pkts[f-1].data, at(f))
		}
	}
	feed(1) // SYN up: no flow yet, nothing pending
	if s := ft.stalledFor(at(1).Add(time.Minute)); s != 0 {
		t.Fatalf("a SYN is demand: %v", s)
	}
	feed(3) // SYN-ACK down: the flow exists
	feed(4) // bare ACK up: not demand
	if s := ft.stalledFor(at(4).Add(time.Minute)); s != 0 {
		t.Fatalf("a bare ACK is demand: %v", s)
	}
	feed(6) // GET up
	if s := ft.stalledFor(at(6).Add(40 * time.Second)); s < 40*time.Second {
		t.Fatalf("an unanswered GET waits %v after 40 s", s)
	}
	feed(9) // ACK down answers it
	if s := ft.stalledFor(at(9).Add(time.Minute)); s != 0 {
		t.Fatalf("an answered flow still waits %v", s)
	}
	feed(11)
	feed(13)
	feed(16) // FIN without data up
	if s := ft.stalledFor(at(16).Add(31 * time.Second)); s < 31*time.Second {
		t.Fatalf("a FIN without data is not demand: %v", s)
	}
	feed(19)
	if s := ft.stalledFor(at(19).Add(time.Minute)); s != 0 {
		t.Fatalf("the final ACK did not answer the FIN: %v", s)
	}
}

// TestZeroWindowProbeIsNotDemand: a one-byte probe into a window the peer
// closed asks nothing of the peer. No probe of that kind is in the captures;
// the closed window is made from the stand's ACK down (frame 9) and the probe
// from its GET (frame 6) with the length cut to one byte.
func TestZeroWindowProbeIsNotDemand(t *testing.T) {
	pkts := fixtureFlows(t)
	closed := append([]byte(nil), pkts[8].data...)
	ihl := int(closed[0]&0x0f) * 4
	binary.BigEndian.PutUint16(closed[ihl+14:], 0)
	probe := append([]byte(nil), pkts[5].data...)
	tcpHdr := int(probe[ihl+12]>>4) * 4
	binary.BigEndian.PutUint16(probe[2:4], uint16(ihl+tcpHdr+1))

	now := pkts[8].at
	ft := newFlowTable()
	ft.down(closed, now)
	ft.up(probe[:ihl+tcpHdr+1], now.Add(time.Second))
	if s := ft.stalledFor(now.Add(time.Minute)); s != 0 {
		t.Fatalf("a window probe counted as demand: %v", s)
	}
	ft.up(pkts[5].data, now.Add(2*time.Second)) // real data still counts
	if s := ft.stalledFor(now.Add(time.Minute)); s == 0 {
		t.Fatal("data into a closed window was not counted")
	}
}

// TestStaleFlowIsNoDemand: demand into a flow not answered for longer than
// stallFlowFresh does not count - the flow may simply be over.
func TestStaleFlowIsNoDemand(t *testing.T) {
	pkts := fixtureFlows(t)
	ft := newFlowTable()
	ft.down(pkts[2].data, pkts[2].at)
	ft.up(pkts[5].data, pkts[2].at.Add(stallFlowFresh+time.Second))
	if s := ft.stalledFor(pkts[2].at.Add(5 * time.Minute)); s != 0 {
		t.Fatalf("demand in a stale flow counted: %v", s)
	}
}

// TestFlowTableEviction: the table stays bounded, and stale idle flows go
// before a flow with demand pending.
func TestFlowTableEviction(t *testing.T) {
	pkts := fixtureFlows(t)
	down, up := pkts[2].data, pkts[5].data
	now := pkts[2].at
	ft := newFlowTable()
	ft.down(down, now)
	ft.up(up, now.Add(time.Second)) // the fixture's flow, pending
	later := now.Add(2 * stallFlowFresh)
	for i := range stallMaxFlows + 50 {
		p := append([]byte(nil), down...)
		ihl := int(p[0]&0x0f) * 4
		binary.BigEndian.PutUint16(p[ihl+0:], uint16(1000+i)) // another remote port
		ft.down(p, later)
	}
	if n := len(ft.flows); n > stallMaxFlows {
		t.Fatalf("%d flows, cap %d", n, stallMaxFlows)
	}
	if s := ft.stalledFor(later); s == 0 {
		t.Fatal("eviction dropped the flow with pending demand before idle ones")
	}
}

// TestFlowTableReset: a new tunnel connection starts with no flows.
func TestFlowTableReset(t *testing.T) {
	pkts := fixtureFlows(t)
	ft := newFlowTable()
	ft.down(pkts[2].data, pkts[2].at)
	ft.up(pkts[5].data, pkts[5].at)
	ft.reset()
	if s := ft.stalledFor(pkts[5].at.Add(time.Minute)); s != 0 {
		t.Fatalf("pending demand survived the reset: %v", s)
	}
}

// slowEchoes is a keepalive peer whose echo takes rtt.
type slowEchoes struct {
	rtt time.Duration
	n   atomic.Uint64
}

func (e *slowEchoes) send() error {
	time.AfterFunc(e.rtt, func() { e.n.Add(1) })
	return nil
}

// TestASlowEchoStillCounts is P2-2 of the round-4 review: the baseline was
// taken anew before the second keepalive, so an echo of the first that came
// after its window - during the pause - was folded into the baseline and
// counted as nothing. On a slow channel both echoes came and the session was
// given up. Window 150 ms, pause 100 ms, echo after 200 ms.
func TestASlowEchoStillCounts(t *testing.T) {
	mon := &stallMonitor{flows: newFlowTable(), echoWait: 150 * time.Millisecond, now: time.Now,
		pause: func() time.Duration { return 100 * time.Millisecond }}
	peer := &slowEchoes{rtt: 200 * time.Millisecond}
	if alive, sent, _ := mon.confirm(make(chan struct{}), peer.send, peer.n.Load); !alive {
		t.Fatalf("both echoes came (%d sent) and the session was given up", sent)
	}
}

// TestALateLastEchoStillCounts: an echo of the last keepalive that lands at
// the very end of its window is still looked for once more.
func TestALateLastEchoStillCounts(t *testing.T) {
	mon := &stallMonitor{flows: newFlowTable(), echoWait: 100 * time.Millisecond, now: time.Now,
		pause: func() time.Duration { return 500 * time.Millisecond }}
	peer := &slowEchoes{rtt: 700 * time.Millisecond}
	if alive, _, _ := mon.confirm(make(chan struct{}), peer.send, peer.n.Load); !alive {
		t.Fatal("an echo landing at the very end of the last window was dropped")
	}
}

// TestEvictionIsAmortized is P3-5 of the round-4 review: at the cap every new
// flow scanned the whole table on the downlink path. Room is now made for an
// eighth of the table at once.
func TestEvictionIsAmortized(t *testing.T) {
	pkts := fixtureFlows(t)
	down := pkts[2].data
	ft := newFlowTable()
	now := pkts[2].at
	const extra = 4 * stallMaxFlows
	for i := range stallMaxFlows + extra {
		p := append([]byte(nil), down...)
		ihl := int(p[0]&0x0f) * 4
		binary.BigEndian.PutUint16(p[ihl:], uint16(i%60000+1))
		binary.BigEndian.PutUint16(p[ihl+2:], uint16(i/60000+1))
		ft.down(p, now.Add(time.Duration(i)*time.Millisecond))
	}
	if max := extra/(stallMaxFlows/8) + 1; ft.evictions > max {
		t.Fatalf("%d full scans for %d new flows past the cap, want at most %d", ft.evictions, extra, max)
	}
	if n := len(ft.flows); n > stallMaxFlows {
		t.Fatalf("%d flows, cap %d", n, stallMaxFlows)
	}
}
