package detect

import (
	"os"
	"strings"
	"testing"
)

// loadFixture reads the captured flow that the whole package is calibrated
// against: TCP stream 96 of test-logs/detect-baseline/ours-reality-dubai.pcap,
// client port 52944. It is the first of the twelve flows nDPI flagged on
// 2026-08-24, and its window [530 4096 267 661] is the one recorded in the
// baseline report.
func loadFixture(t *testing.T) []Packet {
	t.Helper()
	f, err := os.Open("testdata/flow52944.csv")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	streams, err := ParseTSharkCSV(f)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("fixture holds %d streams, want 1", len(streams))
	}
	for _, pkts := range streams {
		return pkts
	}
	return nil
}

// TestFixtureReproducesBaselineFromADump is the test the first version of this
// package was missing.
//
// Every other test here hands the model a hand-written vector, so none of them
// could ever catch a mistake in turning packets into bursts - and that is
// exactly where the bug was: the per-packet deduction used to be a bool
// argument, so a caller analysing a real capture in Plain mode would silently
// get numbers 24 bytes per packet too small. Feeding an actual capture is the
// only way that class of bug shows up.
func TestFixtureReproducesBaselineFromADump(t *testing.T) {
	pkts := loadFixture(t)

	// Port 995 subclassifies as POPS, so TLS is absent from the protocol stack
	// and the flow takes the Plain branch: no gate, no deduction.
	bursts, excluded := Flow{Packets: pkts, Mode: ModePlain}.Bursts()
	if excluded {
		t.Fatal("heuristic excluded the flow; the baseline scored it")
	}

	w, margin, ok := Worst(bursts)
	if !ok {
		t.Fatal("no scoreable window")
	}

	if got, want := w.Bytes(), [4]uint32{530, 4096, 267, 661}; got != want {
		t.Errorf("worst window %v, baseline recorded %v", got, want)
	}
	caught, by := Caught(w)
	if !caught || by != "tls13" {
		t.Errorf("caught=%v by=%q, baseline says caught by tls13", caught, by)
	}
	if margin > -2.0 {
		t.Errorf("margin %.2f, baseline distance 0.815 implies about -2.19", margin)
	}
}

// TestFixtureInTLSInTLSModeIsNotScored shows the other half of the finding: the
// same bytes on a port that resolves to TLS are never scored at all, because
// our data layer only ever writes 0x17 and the gate waits for 0x14.
func TestFixtureInTLSInTLSModeIsNotScored(t *testing.T) {
	pkts := loadFixture(t)

	for _, p := range pkts {
		if p.PayloadLen > 0 && p.FirstByte == 0x14 {
			t.Fatal("fixture contains a 0x14 segment; the premise of this test is that it does not")
		}
	}

	bursts, excluded := Flow{Packets: pkts, Mode: ModeTLSInTLS}.Bursts()
	if excluded {
		// Excluded is also "not scored", which is the point; but say which.
		t.Log("flow excluded before the gate, fine")
		return
	}
	if _, _, ok := Worst(bursts); ok {
		t.Errorf("flow scored in TLS-in-TLS mode with no 0x14 anywhere, bursts=%v", bursts)
	}
}

func TestGateOpensPerDirectionAndSkipsTheSettingPacket(t *testing.T) {
	// c:CCS, c:100, s:CCS, s:200, c:300, s:400, c:500, s:600
	pkts := []Packet{
		{ToServer: true, PayloadLen: 60, FirstByte: 0x14},
		{ToServer: true, PayloadLen: 100, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 60, FirstByte: 0x14},
		{ToServer: false, PayloadLen: 200, FirstByte: 0x17},
		{ToServer: true, PayloadLen: 300, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 400, FirstByte: 0x17},
		{ToServer: true, PayloadLen: 500, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 600, FirstByte: 0x17},
	}

	bursts, excluded := Flow{Packets: pkts, Mode: ModeTLSInTLS}.Bursts()
	if excluded {
		t.Fatal("unexpected exclusion")
	}

	// Each direction gates independently, so the client's 100-byte packet
	// counts as soon as the client's own 0x14 has gone by - it does not wait
	// for the server side to open. The two 0x14 packets themselves never count.
	if len(bursts) == 0 {
		t.Fatal("no bursts")
	}
	if bursts[0].ToServer != true {
		t.Errorf("first burst is server-to-client, want client-to-server")
	}
	// 100 counted, minus 24 of overhead.
	if want := uint32(100 - TLSInTLSOverheadPerPacket); bursts[0].Bytes != want {
		t.Errorf("first burst %d bytes, want %d (100 less the per-packet deduction)", bursts[0].Bytes, want)
	}
	if bursts[0].Pkts != 1 {
		t.Errorf("first burst %d packets, want 1: the 0x14 packet must not be counted", bursts[0].Pkts)
	}
}

func TestGateStaysShutWithoutCCS(t *testing.T) {
	pkts := []Packet{
		{ToServer: true, PayloadLen: 530, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 4096, FirstByte: 0x17},
		{ToServer: true, PayloadLen: 267, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 661, FirstByte: 0x17},
	}
	bursts, _ := Flow{Packets: pkts, Mode: ModeTLSInTLS}.Bursts()
	if len(bursts) != 0 {
		t.Errorf("got %d bursts with no 0x14 in sight, want none", len(bursts))
	}
}

// TestPreGatedByMainDissector covers the second of the two places that set the
// flags: a real CCS record found by reassembly, which arrives here as a field.
func TestPreGatedByMainDissector(t *testing.T) {
	pkts := []Packet{
		{ToServer: true, PayloadLen: 530, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 4096, FirstByte: 0x17},
		{ToServer: true, PayloadLen: 267, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 661, FirstByte: 0x17},
	}
	f := Flow{Packets: pkts, Mode: ModeTLSInTLS, CCSFromClient: true, CCSFromServer: true}
	bursts, excluded := f.Bursts()
	if excluded {
		t.Fatal("unexpected exclusion")
	}
	if len(bursts) != 4 {
		t.Fatalf("got %d bursts, want 4: both flags pre-set means no gate", len(bursts))
	}
	if want := uint32(530 - TLSInTLSOverheadPerPacket); bursts[0].Bytes != want {
		t.Errorf("first burst %d, want %d", bursts[0].Bytes, want)
	}
}

func TestPlainModeDeductsNothing(t *testing.T) {
	pkts := []Packet{
		{ToServer: true, PayloadLen: 530, FirstByte: 0x17},
		{ToServer: false, PayloadLen: 4096, FirstByte: 0x17},
	}
	bursts, _ := Flow{Packets: pkts, Mode: ModePlain}.Bursts()
	if bursts[0].Bytes != 530 {
		t.Errorf("first burst %d, want 530 untouched: Plain mode deducts nothing", bursts[0].Bytes)
	}
}

func TestShortSegmentExcludesInTLSInTLSMode(t *testing.T) {
	pkts := []Packet{
		{ToServer: true, PayloadLen: 60, FirstByte: 0x14},
		{ToServer: false, PayloadLen: 60, FirstByte: 0x14},
		{ToServer: true, PayloadLen: 10, FirstByte: 0x17}, // shorter than the deduction
	}
	if _, excluded := (Flow{Packets: pkts, Mode: ModeTLSInTLS}).Bursts(); !excluded {
		t.Error("a segment shorter than the per-packet deduction must stop the heuristic")
	}
}

func TestMaxPacketsExcludes(t *testing.T) {
	var pkts []Packet
	for i := range 10 {
		pkts = append(pkts, Packet{ToServer: i%2 == 0, PayloadLen: 100, FirstByte: 0x17})
	}
	if _, excluded := (Flow{Packets: pkts, Mode: ModePlain, MaxPackets: 4}).Bursts(); !excluded {
		t.Error("examining more than MaxPackets packets must stop the heuristic")
	}
	if _, excluded := (Flow{Packets: pkts, Mode: ModePlain}).Bursts(); excluded {
		t.Error("MaxPackets == 0 means no limit")
	}
}

func TestParseTSharkCSVReadsFirstByte(t *testing.T) {
	in := strings.Join([]string{
		"0,51000,443,0,",
		"0,51000,443,530,1603010712",
		"0,443,51000,60,140303000101",
		"0,51000,443,281,17",
	}, "\n")

	streams, err := ParseTSharkCSV(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkts := streams["0"]
	if len(pkts) != 4 {
		t.Fatalf("got %d packets, want 4: empty segments are kept", len(pkts))
	}
	if pkts[1].FirstByte != 0x16 || !pkts[1].ToServer {
		t.Errorf("packet 1 = %+v, want first byte 0x16 to server", pkts[1])
	}
	if pkts[2].FirstByte != 0x14 || pkts[2].ToServer {
		t.Errorf("packet 2 = %+v, want first byte 0x14 from server", pkts[2])
	}
}

func TestParseTSharkCSVRejectsGarbage(t *testing.T) {
	if _, err := ParseTSharkCSV(strings.NewReader("0,51000,443,notanumber,17")); err == nil {
		t.Error("accepted a non-numeric tcp.len")
	}
	if _, err := ParseTSharkCSV(strings.NewReader("0,51000,443,10,zz")); err == nil {
		t.Error("accepted a non-hex payload")
	}
}
