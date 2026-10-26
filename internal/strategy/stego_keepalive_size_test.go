package strategy

import (
	"fmt"
	"maps"
	"math"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// dataSizes reads frames off the far end of a stego conn's pipe and sends
// the payload length of each DATA frame, HEADERS and the rest skipped.
func dataSizes(t *testing.T, far net.Conn) <-chan int {
	t.Helper()
	out := make(chan int, 4096)
	fr := http2.NewFramer(nil, far)
	fr.AllowIllegalReads = true
	go func() {
		defer close(out)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if d, ok := f.(*http2.DataFrame); ok {
				out <- len(d.Data())
			}
		}
	}()
	return out
}

// stegoSizeConn is a relay-side upstream stego conn - the standard padding
// of server/upstream.go, so not the TUN fast path - over a pipe, with the
// payload lengths of what it writes.
func stegoSizeConn(t *testing.T) (*HTTP2StegoConn, <-chan int) {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	sc := NewHTTP2StegoConn(near, []byte("relay-leg-secret-0123456789abcdef"), true, NaivePaddingStandard, nil)
	if sc.tunMode {
		t.Fatal("the upstream conn runs the TUN fast path - the test proves nothing")
	}
	return sc, dataSizes(t, far)
}

func histogram(sizes []int) map[int]int {
	h := make(map[int]int)
	for _, s := range sizes {
		h[s]++
	}
	return h
}

func histogramString(h map[int]int) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(h)) {
		fmt.Fprintf(&b, " %d B: %d;", k, h[k])
	}
	return b.String()
}

// TestARelaysOwnKeepaliveIsTheSizeOfARelayedOne is P3-6 of the round-9
// review. Up a relay's leg go two kinds of empty-looking frame: the relay's
// own keepalive (KeepAlive, no payload) and its client's TUN keepalive it
// forwards ([0,0,0,0], a 4-byte payload). Both got the 10-byte cover floor,
// so the relay's own was 4 bytes shorter, every time, and the size alone
// told them apart. Through the real framer, 500 of each, the keepalive
// written by KeepAlive itself: the two size distributions must be one.
func TestARelaysOwnKeepaliveIsTheSizeOfARelayedOne(t *testing.T) {
	const n = 500

	own, ownSizes := stegoSizeConn(t)
	own.lastOwnerWrite.Store(stegoMono()) // KeepAlive sends only after the owner has written
	go own.KeepAlive(func() time.Duration { return time.Millisecond }, func() bool { return true }, nil)
	var ownGot []int
	for len(ownGot) < n {
		select {
		case s := <-ownSizes:
			ownGot = append(ownGot, s)
		case <-time.After(10 * time.Second):
			t.Fatalf("%d keepalives in 10 s", len(ownGot))
		}
	}
	own.Close()

	relayed, relayedSizes := stegoSizeConn(t)
	var relayedGot []int
	go func() {
		for range n {
			if _, err := relayed.Write([]byte{0, 0, 0, 0}); err != nil {
				return
			}
		}
	}()
	for len(relayedGot) < n {
		select {
		case s := <-relayedSizes:
			relayedGot = append(relayedGot, s)
		case <-time.After(10 * time.Second):
			t.Fatalf("%d relayed keepalives in 10 s", len(relayedGot))
		}
	}

	oh, rh := histogram(ownGot), histogram(relayedGot)
	t.Logf("own keepalive:%s", histogramString(oh))
	t.Logf("relayed [0,0,0,0]:%s", histogramString(rh))
	// The marker's length is flat over 16 values, so each kind spreads over
	// 16 sizes; what must match is where and how. The same smallest and
	// largest size, and the two-sample Kolmogorov-Smirnov distance under
	// its 0.1% critical value: the 4-byte gap was a distance near 0.25.
	if slices.Min(ownGot) != slices.Min(relayedGot) || slices.Max(ownGot) != slices.Max(relayedGot) {
		t.Fatalf("own keepalive %d-%d B, relayed %d-%d B:\nown:%s\nrelayed:%s",
			slices.Min(ownGot), slices.Max(ownGot), slices.Min(relayedGot), slices.Max(relayedGot),
			histogramString(oh), histogramString(rh))
	}
	if d, crit := ksDistance(ownGot, relayedGot), 1.95*math.Sqrt(2/float64(n)); d > crit {
		t.Fatalf("size distributions differ: KS %.3f > %.3f:\nown:%s\nrelayed:%s", d, crit, histogramString(oh), histogramString(rh))
	}
}

// ksDistance is the two-sample Kolmogorov-Smirnov statistic of a and b.
func ksDistance(a, b []int) float64 {
	a, b = slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b))
	var d float64
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		x := min(a[i], b[j])
		for i < len(a) && a[i] == x {
			i++
		}
		for j < len(b) && b[j] == x {
			j++
		}
		d = max(d, math.Abs(float64(i)/float64(len(a))-float64(j)/float64(len(b))))
	}
	return d
}
