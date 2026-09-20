package wiretest

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// Finding is one hit: what matched, and enough context to see it in a failure
// message without dumping the whole capture.
type Finding struct {
	Where   string // human-readable position, e.g. "c2s offset 52"
	Excerpt string
}

func (f Finding) String() string {
	if f.Excerpt == "" {
		return f.Where
	}
	return f.Where + ": " + f.Excerpt
}

// excerpt renders up to n bytes around off as a printable string.
func excerpt(b []byte, off, n int) string {
	lo := off - 8
	if lo < 0 {
		lo = 0
	}
	hi := off + n
	if hi > len(b) {
		hi = len(b)
	}
	var sb strings.Builder
	for _, c := range b[lo:hi] {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return fmt.Sprintf("%q", sb.String())
}

// Literal reports the first occurrence of needle in one direction of the dump.
func Literal(d *Dump, dir Direction, needle string) (Finding, bool) {
	b := d.Bytes(dir)
	i := bytes.Index(b, []byte(needle))
	if i < 0 {
		return Finding{}, false
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s offset %d of %d", d.Layer, dir, i, len(b)),
		Excerpt: excerpt(b, i, len(needle)+8),
	}, true
}

// LiteralWithin reports the first occurrence of needle in the first n bytes of
// one direction. Used for "this marker sits in the opening bytes", which is a
// stronger claim than "it appears somewhere in the session".
func LiteralWithin(d *Dump, dir Direction, needle string, n int) (Finding, bool) {
	b := d.Bytes(dir)
	if len(b) > n {
		b = b[:n]
	}
	i := bytes.Index(b, []byte(needle))
	if i < 0 {
		return Finding{}, false
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s offset %d (first %d bytes)", d.Layer, dir, i, n),
		Excerpt: excerpt(b, i, len(needle)+8),
	}, true
}

// PrefixAt reports whether the direction's stream starts with prefix.
func PrefixAt(d *Dump, dir Direction, prefix string) (Finding, bool) {
	b := d.Bytes(dir)
	if !bytes.HasPrefix(b, []byte(prefix)) {
		return Finding{}, false
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s offset 0", d.Layer, dir),
		Excerpt: excerpt(b, 0, len(prefix)+8),
	}, true
}

// H2DataPayloadPrefix walks the HTTP/2 frames in one direction and reports the
// first DATA frame whose payload starts with prefix.
//
// It parses frames rather than scanning bytes on purpose: "the four bytes TIRD
// appear somewhere in the stream" and "every DATA frame opens with TIRD" are
// different findings, and only the second one is the fingerprint.
func H2DataPayloadPrefix(d *Dump, dir Direction, prefix string) (Finding, bool) {
	b := d.Bytes(dir)
	b = bytes.TrimPrefix(b, []byte(http2.ClientPreface))

	fr := http2.NewFramer(io.Discard, bytes.NewReader(b))
	fr.AllowIllegalReads = true
	fr.SetMaxReadFrameSize(1 << 20)

	seen := 0
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		df, ok := f.(*http2.DataFrame)
		if !ok {
			continue
		}
		seen++
		payload := df.Data()
		if bytes.HasPrefix(payload, []byte(prefix)) {
			return Finding{
				Where: fmt.Sprintf("%s %s DATA frame #%d (stream %d, %d bytes) payload offset 0",
					d.Layer, dir, seen, df.StreamID, len(payload)),
				Excerpt: excerpt(payload, 0, len(prefix)+8),
			}, true
		}
	}
	return Finding{}, false
}

// LoneByte reports a chunk that consists of exactly one byte equal to want,
// preceded by at least minPrefix bytes in that direction.
//
// A one-byte write on a NODELAY socket is its own TCP segment, and a lone
// segment carrying a constant at a fixed point in the handshake is a
// fingerprint that needs no parsing at all.
func LoneByte(d *Dump, dir Direction, want byte, minPrefix int) (Finding, bool) {
	off := 0
	for _, s := range d.Segments() {
		if s.Dir != dir {
			continue
		}
		if len(s.Data) == 1 && s.Data[0] == want && off >= minPrefix {
			return Finding{
				Where:   fmt.Sprintf("%s %s offset %d", d.Layer, dir, off),
				Excerpt: fmt.Sprintf("single-byte segment 0x%02x", want),
			}, true
		}
		off += len(s.Data)
	}
	return Finding{}, false
}

// Grid reports a run of at least minRun consecutive chunks of exactly pitch
// bytes — a writer emitting a fixed-size fragment train.
//
// Formulated as a run rather than as "every boundary is on the grid" because
// read() coalescing merges chunks: the kernel may hand two 200-byte writes back
// as one 400-byte read, which erases a boundary. Coalescing can therefore turn
// a true positive into a negative, never the reverse, and a run of consecutive
// identical chunk sizes is something a randomised writer does not produce by
// accident. Callers make up for the false negatives by sampling more than one
// connection.
func Grid(d *Dump, dir Direction, pitch, minRun int) (Finding, bool) {
	sizes := d.Sizes(dir)

	best, run, bestEnd := 0, 0, 0
	for i, n := range sizes {
		if n == pitch {
			run++
			if run > best {
				best, bestEnd = run, i
			}
			continue
		}
		run = 0
	}
	if best < minRun {
		return Finding{}, false
	}

	off := 0
	for _, n := range sizes[:bestEnd-best+1] {
		off += n
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s chunk sizes %v", d.Layer, dir, sizes),
		Excerpt: fmt.Sprintf("%d consecutive %d-byte chunks starting at offset %d", best, pitch, off),
	}, true
}

// SameStream reports whether two dumps carry byte-identical traffic in one
// direction up to n bytes. Two sessions of the same client that produce the
// same bytes are trivially linkable, and a censor does not need to break any
// crypto to do it.
func SameStream(a, b *Dump, dir Direction, n int) (Finding, bool) {
	x, y := a.Bytes(dir), b.Bytes(dir)
	if len(x) < n || len(y) < n {
		return Finding{}, false
	}
	if !bytes.Equal(x[:n], y[:n]) {
		return Finding{}, false
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s first %d bytes", a.Layer, dir, n),
		Excerpt: "two independent connections produced identical bytes",
	}, true
}

// SameSizes reports whether two dumps show the same chunk boundaries in one
// direction, ignoring any leading chunks the caller already accounted for.
func SameSizes(a, b *Dump, dir Direction, skip int) (Finding, bool) {
	x, y := a.Sizes(dir), b.Sizes(dir)
	if len(x) <= skip || len(x) != len(y) {
		return Finding{}, false
	}
	for i := skip; i < len(x); i++ {
		if x[i] != y[i] {
			return Finding{}, false
		}
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s sizes %v", a.Layer, dir, x[skip:]),
		Excerpt: "identical chunk sizes across two connections",
	}, true
}

// SameGaps reports whether the inter-chunk delays of two dumps agree within
// tol. Delays derived from a key are as much a fingerprint as sizes are, and
// they survive any amount of payload encryption.
func SameGaps(a, b *Dump, dir Direction, skip int, tol time.Duration) (Finding, bool) {
	x, y := a.Gaps(dir), b.Gaps(dir)
	if len(x) <= skip || len(x) != len(y) {
		return Finding{}, false
	}
	for i := skip; i < len(x); i++ {
		diff := x[i] - y[i]
		if diff < 0 {
			diff = -diff
		}
		if diff > tol {
			return Finding{}, false
		}
	}
	return Finding{
		Where:   fmt.Sprintf("%s %s gaps %v", a.Layer, dir, x[skip:]),
		Excerpt: fmt.Sprintf("inter-chunk delays repeat within %v", tol),
	}, true
}

// LenSample pairs one carried payload's plaintext length with the length of the
// record that carried it.
type LenSample struct {
	Inner  int // plaintext / inner packet length
	Record int // observed record (framing) length
}

// LengthTracksPayload reports whether the record length betrays the inner packet
// length: it splits the samples at the midpoint inner size and fires when the
// record-length range of the small-packet half is disjoint from the large-packet
// half. Disjoint ranges mean a censor can read the packet size straight off the
// record size - the packet-length distribution (which fingerprints the traffic:
// bulk vs interactive vs tunnel) leaks through a padding scheme that only ever
// adds a fixed offset. Overlapping ranges mean the record size no longer pins
// the packet size.
//
// It is deliberately a range-overlap test, not a Pearson correlation: additive
// random padding leaves correlation near 1 while genuinely bucketed padding lets
// a small packet occasionally occupy a large record, which is exactly the
// overlap this looks for.
func LengthTracksPayload(samples []LenSample) (Finding, bool) {
	if len(samples) < 8 {
		return Finding{}, false
	}
	minInner, maxInner := math.MaxInt, math.MinInt
	for _, s := range samples {
		if s.Inner < minInner {
			minInner = s.Inner
		}
		if s.Inner > maxInner {
			maxInner = s.Inner
		}
	}
	if maxInner == minInner {
		return Finding{}, false // no spread of inner sizes to separate
	}
	threshold := (minInner + maxInner) / 2

	smallMin, smallMax := math.MaxInt, math.MinInt
	largeMin, largeMax := math.MaxInt, math.MinInt
	for _, s := range samples {
		if s.Inner <= threshold {
			if s.Record < smallMin {
				smallMin = s.Record
			}
			if s.Record > smallMax {
				smallMax = s.Record
			}
		} else {
			if s.Record < largeMin {
				largeMin = s.Record
			}
			if s.Record > largeMax {
				largeMax = s.Record
			}
		}
	}
	if smallMax < smallMin || largeMax < largeMin {
		return Finding{}, false // one half empty
	}
	if smallMin <= largeMax && largeMin <= smallMax {
		return Finding{}, false // ranges overlap: record size does not pin packet size
	}
	return Finding{
		Where: "framing record length vs inner packet length",
		Excerpt: fmt.Sprintf("small packets occupy records %d..%d, large packets %d..%d (disjoint): "+
			"the record length reveals the packet length", smallMin, smallMax, largeMin, largeMax),
	}, true
}

// Contains is a plain substring check over a string slice, for ALPN lists and
// other parsed (rather than captured) evidence.
func Contains(list []string, want string) (Finding, bool) {
	for _, s := range list {
		if s == want {
			return Finding{
				Where:   "clienthello alpn",
				Excerpt: fmt.Sprintf("%v", list),
			}, true
		}
	}
	return Finding{}, false
}
