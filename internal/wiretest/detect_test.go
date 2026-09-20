// detect_test.go guards the instrument, not the code under test.
//
// The signature tests are positive controls for the strategies; these are
// positive AND negative controls for the matchers themselves. A matcher that
// says "yes" to everything would make every signature test green and every
// future "the marker is gone" green too — which is precisely the failure the
// whole harness exists to prevent.
package wiretest_test

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tiredvpn/tiredvpn/internal/wiretest"
)

// dumpOf builds a dump from a list of client→server chunks.
func dumpOf(chunks ...[]byte) *wiretest.Dump {
	d := wiretest.NewDump("synthetic", wiretest.LayerTCP)
	for _, c := range chunks {
		d.Record(wiretest.C2S, c)
	}
	return d
}

func TestLiteralWithinRespectsTheWindow(t *testing.T) {
	d := dumpOf(bytes.Repeat([]byte{0}, 100), []byte("TIRED"))

	if _, ok := wiretest.LiteralWithin(d, wiretest.C2S, "TIRED", 256); !ok {
		t.Error("marker at offset 100 not found in a 256-byte window")
	}
	if _, ok := wiretest.LiteralWithin(d, wiretest.C2S, "TIRED", 64); ok {
		t.Error("marker at offset 100 reported inside a 64-byte window")
	}
	if _, ok := wiretest.LiteralWithin(d, wiretest.C2S, "TIRED", 256); !ok {
		t.Error("repeat lookup disagreed with the first")
	}
	if _, ok := wiretest.Literal(d, wiretest.S2C, "TIRED"); ok {
		t.Error("client bytes reported in the server direction")
	}
}

func TestGridNeedsARunOfExactChunks(t *testing.T) {
	sized := func(ns ...int) *wiretest.Dump {
		var chunks [][]byte
		for _, n := range ns {
			chunks = append(chunks, make([]byte, n))
		}
		return dumpOf(chunks...)
	}

	if _, ok := wiretest.Grid(sized(930, 200, 200, 200, 15), wiretest.C2S, 200, 3); !ok {
		t.Error("three consecutive 200-byte chunks not recognised")
	}
	// Coalescing erases boundaries: 400 is two merged fragments, and the run is
	// then too short. A false negative here is the acceptable direction.
	if _, ok := wiretest.Grid(sized(930, 400, 200, 15), wiretest.C2S, 200, 3); ok {
		t.Error("a run of one was accepted as a grid")
	}
	// A randomised writer must not match.
	if _, ok := wiretest.Grid(sized(930, 173, 241, 198, 200, 15), wiretest.C2S, 200, 3); ok {
		t.Error("random chunk sizes matched the 200-byte grid")
	}
}

func TestLoneByteWantsItsOwnChunk(t *testing.T) {
	head := make([]byte, 50)

	if _, ok := wiretest.LoneByte(dumpOf(head, []byte{0x08}), wiretest.C2S, 0x08, 50); !ok {
		t.Error("a single-byte chunk after 50 bytes was not found")
	}
	// Same byte at the same offset, but riding along with the next write: the
	// lone-segment claim is false and the matcher has to say so.
	if _, ok := wiretest.LoneByte(dumpOf(head, []byte{0x08, 0x01}), wiretest.C2S, 0x08, 50); ok {
		t.Error("a two-byte chunk was reported as a lone byte")
	}
	// Right shape, wrong value.
	if _, ok := wiretest.LoneByte(dumpOf(head, []byte{0x07}), wiretest.C2S, 0x08, 50); ok {
		t.Error("0x07 matched a request for 0x08")
	}
	// Right shape and value, but before the handshake is over.
	if _, ok := wiretest.LoneByte(dumpOf([]byte{0x08}, head), wiretest.C2S, 0x08, 50); ok {
		t.Error("a lone byte before minPrefix was accepted")
	}
}

func TestSameStreamAndSizesSeparateTwoConnections(t *testing.T) {
	a := dumpOf([]byte{1}, []byte("aaaa"), []byte("bb"))
	same := dumpOf([]byte{9}, []byte("aaaa"), []byte("bb"))
	diffBytes := dumpOf([]byte{1}, []byte("axaa"), []byte("bb"))
	diffSizes := dumpOf([]byte{1}, []byte("aaa"), []byte("bbb"))

	if _, ok := wiretest.SameSizes(a, same, wiretest.C2S, 1); !ok {
		t.Error("identical chunk sizes past the skipped prefix were not recognised")
	}
	if _, ok := wiretest.SameSizes(a, diffSizes, wiretest.C2S, 1); ok {
		t.Error("different chunk sizes reported as identical")
	}
	if _, ok := wiretest.SameStream(a, diffBytes, wiretest.C2S, 7); ok {
		t.Error("streams differing by one byte reported as identical")
	}
}

func TestSameGapsHonoursTolerance(t *testing.T) {
	timed := func(gaps ...time.Duration) *wiretest.Dump {
		d := wiretest.NewDump("synthetic", wiretest.LayerTCP)
		d.Record(wiretest.C2S, []byte{0})
		for _, g := range gaps {
			time.Sleep(g)
			d.Record(wiretest.C2S, []byte{0})
		}
		return d
	}

	a := timed(20*time.Millisecond, 40*time.Millisecond)
	b := timed(20*time.Millisecond, 40*time.Millisecond)
	c := timed(20*time.Millisecond, 200*time.Millisecond)

	if _, ok := wiretest.SameGaps(a, b, wiretest.C2S, 0, 30*time.Millisecond); !ok {
		t.Error("the same nominal delays were not recognised as repeating")
	}
	if _, ok := wiretest.SameGaps(a, c, wiretest.C2S, 0, 30*time.Millisecond); ok {
		t.Error("a 160ms difference passed a 30ms tolerance")
	}
}

func TestH2DataPayloadPrefixParsesFramesNotBytes(t *testing.T) {
	build := func(payload []byte) *wiretest.Dump {
		var buf bytes.Buffer
		buf.WriteString(http2.ClientPreface)
		fr := http2.NewFramer(&buf, nil)
		fr.AllowIllegalWrites = true
		if err := fr.WriteData(1, false, payload); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
		return dumpOf(buf.Bytes())
	}

	if _, ok := wiretest.H2DataPayloadPrefix(build([]byte("TIRDxxxx")), wiretest.C2S, "TIRD"); !ok {
		t.Error("a DATA payload starting with the magic was not found")
	}
	// The literal is present in the stream but not at offset 0 of the payload,
	// which is the whole difference between a fingerprint and a coincidence.
	if _, ok := wiretest.H2DataPayloadPrefix(build([]byte("xxTIRDxx")), wiretest.C2S, "TIRD"); ok {
		t.Error("the magic was reported although it is not the payload prefix")
	}
	if _, ok := wiretest.H2DataPayloadPrefix(build([]byte("grpcxxxx")), wiretest.C2S, "TIRD"); ok {
		t.Error("an unrelated payload matched the magic")
	}
}
