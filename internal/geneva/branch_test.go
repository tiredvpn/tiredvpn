package geneva

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- the branch mechanism itself ----------------------------------------

// markPrimitive stamps a recognisable byte into the packet's TOS field and
// records which packets it was handed. It exists because the branch machinery
// had never executed before: Branches was declared, AddBranch was written, and
// git grep found no caller of either anywhere in the tree. Building the
// strategies on top of a mechanism in that state without testing the mechanism
// first would only move the defect.
type markPrimitive struct {
	mark byte
	seen [][]byte
}

func (m *markPrimitive) Apply(packet []byte) ([][]byte, error) {
	m.seen = append(m.seen, append([]byte(nil), packet...))
	out := make([]byte, len(packet))
	copy(out, packet)
	out[1] = m.mark
	return [][]byte{out}, nil
}

func (m *markPrimitive) String() string { return "mark" }

// TestActionTreeBranchesRouteResultsIndividually is the guard on the mechanism:
// result i must reach branch i and no other branch.
//
// The old implementation ran every branch over every result, a cross product.
// With two results and two branches that produced four packets instead of two,
// and every branch saw every packet - which is exactly the property the
// strategies need not to hold.
func TestActionTreeBranchesRouteResultsIndividually(t *testing.T) {
	packet := createTestPacket()

	left := &markPrimitive{mark: 0xA1}
	right := &markPrimitive{mark: 0xB2}

	tree := NewActionTree(NewDuplicatePrimitive(1))
	tree.AddBranch(NewActionTree(left))
	tree.AddBranch(NewActionTree(right))

	results, err := tree.Execute(packet)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Execute returned %d packets, want 2 - branches are being run over every result", len(results))
	}
	if len(left.seen) != 1 {
		t.Errorf("branch 0 was handed %d packets, want exactly 1", len(left.seen))
	}
	if len(right.seen) != 1 {
		t.Errorf("branch 1 was handed %d packets, want exactly 1", len(right.seen))
	}
	if results[0][1] != 0xA1 {
		t.Errorf("result 0 carries mark %#x, want %#x from branch 0", results[0][1], 0xA1)
	}
	if results[1][1] != 0xB2 {
		t.Errorf("result 1 carries mark %#x, want %#x from branch 1", results[1][1], 0xB2)
	}
}

// TestActionTreeSurplusResultsGoToLastBranch pins what happens when the root
// produces more results than there are branches, which is what
// duplicate{count=N} with a clean branch and a tamper branch relies on.
func TestActionTreeSurplusResultsGoToLastBranch(t *testing.T) {
	packet := createTestPacket()

	clean := &markPrimitive{mark: 0x11}
	tampered := &markPrimitive{mark: 0x22}

	tree := NewActionTree(NewDuplicatePrimitive(3)) // original + 3 copies
	tree.AddBranch(NewActionTree(clean))
	tree.AddBranch(NewActionTree(tampered))

	results, err := tree.Execute(packet)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("Execute returned %d packets, want 4", len(results))
	}
	if len(clean.seen) != 1 {
		t.Errorf("the first branch took %d packets, want 1", len(clean.seen))
	}
	if len(tampered.seen) != 3 {
		t.Errorf("the last branch took %d packets, want the 3 surplus copies", len(tampered.seen))
	}
}

// TestActionTreeWithoutBranchesIsUnchanged guards the path every
// fragment-only strategy still takes.
func TestActionTreeWithoutBranchesIsUnchanged(t *testing.T) {
	packet := createTestPacket()

	tree := NewActionTree(NewDuplicatePrimitive(1))
	results, err := tree.Execute(packet)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("a branchless duplicate returned %d packets, want 2", len(results))
	}
	for i, r := range results {
		if !bytes.Equal(r, packet) {
			t.Errorf("branchless result %d differs from the input packet", i)
		}
	}
}

// --- the strategies -----------------------------------------------------

func ipTTL(p []byte) byte    { return p[8] }
func tcpFlags(p []byte) byte { return p[33] }
func tcpSeq(p []byte) uint32 { return binary.BigEndian.Uint32(p[24:28]) }
func synPacket() []byte      { p := createTestPacket(); p[33] = TCPFlagSYN; return p }
func pshAckPacket() []byte   { p := createTestPacket(); p[33] = TCPFlagPSH | TCPFlagACK; return p }

// TestPacketStrategiesLeaveTheRealPacketIntact is the core regression guard for
// C2, and it is deliberately a table over every duplicate-based strategy rather
// than one example. All six were built from the same chained form and all six
// were broken; a test covering only the first would have let the other five
// through, which is how the defect survived this long.
//
// For each one: exactly two packets go out, exactly one of them is byte-for-byte
// the packet that was handed in, and the other carries the intended
// manipulation. Checking only "one packet is unchanged" would pass on a
// strategy that manipulated nothing at all, so the decoy assertion is paired
// with it.
func TestPacketStrategiesLeaveTheRealPacketIntact(t *testing.T) {
	tests := []struct {
		name     string
		strategy *Strategy
		packet   []byte
		// decoyOK reports whether the emitted decoy carries the manipulation
		// this strategy exists to make.
		decoyOK func(decoy []byte) bool
		want    string
	}{
		{
			name: "china_gfw_1 low-TTL SYN decoy", strategy: ChinaGFWStrategy1(), packet: synPacket(),
			decoyOK: func(d []byte) bool { return ipTTL(d) == 10 }, want: "TTL 10",
		},
		{
			name: "china_gfw_2 fake SYN-ACK decoy", strategy: ChinaGFWStrategy2(), packet: synPacket(),
			decoyOK: func(d []byte) bool { return tcpFlags(d) == TCPFlagSYN|TCPFlagACK }, want: "flags SYN|ACK",
		},
		{
			name: "iran_dpi_1 desync seq decoy", strategy: IranDPIStrategy1(), packet: synPacket(),
			decoyOK: func(d []byte) bool { return tcpSeq(d) == 10000 }, want: "seq 10000",
		},
		{
			name: "russia_tspu_1 TTL-8 SYN decoy", strategy: RussiaTSPUStrategy1(), packet: synPacket(),
			decoyOK: func(d []byte) bool { return ipTTL(d) == 8 }, want: "TTL 8",
		},
		{
			name: "russia_tspu_3 RST decoy", strategy: RussiaTSPUStrategy3(), packet: pshAckPacket(),
			decoyOK: func(d []byte) bool { return tcpFlags(d) == TCPFlagRST }, want: "flags RST",
		},
		{
			name: "turkey_dpi_1 zero-seq decoy", strategy: TurkeyDPIStrategy1(), packet: synPacket(),
			decoyOK: func(d []byte) bool { return tcpSeq(d) == 0 }, want: "seq 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := append([]byte(nil), tt.packet...)

			results, err := tt.strategy.Apply(tt.packet, true)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(results) != 2 {
				t.Fatalf("Apply emitted %d packets, want 2 (one decoy, one real)", len(results))
			}

			// The caller's buffer must survive untouched, not just some copy of it.
			if !bytes.Equal(tt.packet, before) {
				t.Errorf("Apply modified the packet it was handed, in place")
			}

			var intact, decoys int
			var decoy []byte
			for _, r := range results {
				if bytes.Equal(r, before) {
					intact++
				} else {
					decoys++
					decoy = r
				}
			}
			if intact != 1 {
				t.Fatalf("%d of the %d emitted packets are the original; want exactly 1 - "+
					"the manipulation is landing on the real packet and the connection will not survive it",
					intact, len(results))
			}
			if decoys != 1 {
				t.Fatalf("%d emitted packets differ from the original, want exactly 1", decoys)
			}
			if !tt.decoyOK(decoy) {
				t.Errorf("the decoy does not carry %s - the strategy manipulates nothing", tt.want)
			}
		})
	}
}

// TestDecoyIsSentBeforeTheRealPacket pins the ordering. A decoy that arrives
// after the packet it was meant to shield has nothing left to poison, so the
// order is part of the behaviour and not an accident of how the tree is built.
func TestDecoyIsSentBeforeTheRealPacket(t *testing.T) {
	for _, tt := range []struct {
		name     string
		strategy *Strategy
		packet   []byte
	}{
		{"china_gfw_1", ChinaGFWStrategy1(), synPacket()},
		{"china_gfw_2", ChinaGFWStrategy2(), synPacket()},
		{"iran_dpi_1", IranDPIStrategy1(), synPacket()},
		{"russia_tspu_1", RussiaTSPUStrategy1(), synPacket()},
		{"russia_tspu_3", RussiaTSPUStrategy3(), pshAckPacket()},
		{"turkey_dpi_1", TurkeyDPIStrategy1(), synPacket()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := append([]byte(nil), tt.packet...)
			results, err := tt.strategy.Apply(tt.packet, true)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(results) != 2 {
				t.Fatalf("Apply emitted %d packets, want 2", len(results))
			}
			if bytes.Equal(results[0], before) {
				t.Errorf("the real packet goes out first; the decoy behind it poisons nothing")
			}
			if !bytes.Equal(results[1], before) {
				t.Errorf("the second packet is not the untouched original")
			}
		})
	}
}

// TestFragmentStrategiesUnaffected checks the three strategies that never had
// the defect still behave: they carry no duplicate, so nothing should route
// through branches at all.
func TestFragmentStrategiesUnaffected(t *testing.T) {
	for _, tt := range []struct {
		name     string
		strategy *Strategy
	}{
		{"china_gfw_3", ChinaGFWStrategy3()},
		{"iran_dpi_2", IranDPIStrategy2()},
		{"russia_tspu_2", RussiaTSPUStrategy2()},
		{"generic_fragment", GenericFragmentStrategy()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet := pshAckPacket()
			before := append([]byte(nil), packet...)

			results, err := tt.strategy.Apply(packet, true)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(results) != 2 {
				t.Fatalf("Apply emitted %d packets, want 2 fragments", len(results))
			}
			if !bytes.Equal(packet, before) {
				t.Errorf("Apply modified the packet it was handed, in place")
			}
			// Fragments carry the payload between them, so neither is the original.
			for i, r := range results {
				if bytes.Equal(r, before) {
					t.Errorf("fragment %d is the whole original packet - nothing was fragmented", i)
				}
			}
		})
	}
}

// TestNoStrategyClaimsASuccessRate sweeps the whole registry rather than the
// handful the older metadata test covered: the invented percentages were in all
// eleven, and one left behind would be quoted as fact by
// GenevaStrategy.Description.
func TestNoStrategyClaimsASuccessRate(t *testing.T) {
	for name, s := range GetAllStrategies() {
		if rate := s.GetSuccessRate(); rate != "unmeasured" {
			t.Errorf("%s: GetSuccessRate() = %q, want %q", name, rate, "unmeasured")
		}
		if s.Trigger.Metadata != nil {
			if v, ok := s.Trigger.Metadata["success_rate"]; ok {
				t.Errorf("%s: metadata still carries success_rate=%q", name, v)
			}
		}
	}
}
