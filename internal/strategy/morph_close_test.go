package strategy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

// chunkShaper cuts a write into fixed-size frames with no delay between
// them: the queue then moves as fast as the peer reads, which isolates
// Close from the shaper's pacing.
type chunkShaper struct{ constShaper }

func (s *chunkShaper) Wrap(p []byte) [][]byte {
	var frames [][]byte
	for len(p) > 0 {
		n := min(len(p), 1200)
		frames = append(frames, p[:n])
		p = p[n:]
	}
	return frames
}

func closeTestShaper(t *testing.T, preset string, seed int64) shaper.Shaper {
	t.Helper()
	sh, err := ShaperFromConfig(&toml.ShaperConfig{Preset: preset, Seed: &seed})
	if err != nil {
		t.Fatalf("ShaperFromConfig(%q): %v", preset, err)
	}
	return sh
}

func closeTestPayload(n int) []byte {
	rng := rand.New(rand.NewPCG(0x5EED, uint64(n)))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.UintN(256))
	}
	return b
}

// writeThenClose writes payload on a fresh MorphedConn pair over net.Pipe
// and closes the writer as soon as Write returns, the way a real caller
// does, while the peer reads slowly: readPause after every 4 KiB. It
// returns what the peer got before EOF, how long Close took and what it
// returned.
func writeThenClose(t *testing.T, client, server *MorphedConn, payload []byte, readPause time.Duration) ([]byte, time.Duration, error) {
	t.Helper()
	type result struct {
		got []byte
		err error
	}
	readc := make(chan result, 1)
	go func() {
		var got []byte
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				readc <- result{got, err}
				return
			}
			time.Sleep(readPause)
		}
	}()

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	start := time.Now()
	closeErr := client.Close()
	took := time.Since(start)

	select {
	case r := <-readc:
		if !errors.Is(r.err, io.EOF) && !errors.Is(r.err, io.ErrClosedPipe) {
			t.Fatalf("peer read ended with %v, want EOF", r.err)
		}
		return r.got, took, closeErr
	case <-time.After(30 * time.Second):
		t.Fatal("the peer never saw the close")
		return nil, 0, nil
	}
}

// TestMorphedConnCloseDeliversTail is the regression for Close dropping the
// tail: it drained the pacer queue for at most 100 ms, checked that bound
// only between writev batches, released whatever was left and returned nil.
// Over net.Pipe with a slow reader 1 MiB lost about 86 KB that way, and the
// chrome preset with a reader pausing 1 ms per 4 KiB about 88 KB, with
// Close taking 267 ms past its bound. Now Close must hand over every byte
// Write accepted and return nil.
func TestMorphedConnCloseDeliversTail(t *testing.T) {
	profile := &TrafficProfile{Name: "T", PacketSizes: []int{1200}, PacketSizeProbs: []float64{1.0}}
	cases := []struct {
		name      string
		client    func(t *testing.T) shaper.Shaper
		server    func(t *testing.T) shaper.Shaper
		readPause time.Duration
	}{
		{
			name:      "unpaced, slow reader",
			client:    func(*testing.T) shaper.Shaper { return &chunkShaper{} },
			server:    func(*testing.T) shaper.Shaper { return &chunkShaper{} },
			readPause: 2 * time.Millisecond,
		},
		{
			name:      "chrome preset, reader pausing 1 ms per 4 KiB",
			client:    func(t *testing.T) shaper.Shaper { return closeTestShaper(t, presets.PresetChromeBrowsing, 1) },
			server:    func(t *testing.T) shaper.Shaper { return closeTestShaper(t, presets.PresetChromeBrowsing, 2) },
			readPause: time.Millisecond,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cleanup := NewTestMorphedConnPair(profile, tc.client(t), tc.server(t))
			defer cleanup()

			want := closeTestPayload(1 << 20)
			got, took, closeErr := writeThenClose(t, client, server, want, tc.readPause)
			if closeErr != nil {
				t.Fatalf("Close after %v: %v, want nil with a peer that reads", took, closeErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("peer got %d of %d bytes (Close returned nil after %v)", len(got), len(want), took)
			}
		})
	}
}

// TestMorphedConnCloseReportsUndelivered: a peer that stops reading must
// neither hold Close forever nor let it lose the queue silently. Close
// returns within the close timeout with ErrShaperCloseIncomplete, and the
// byte count it reports is exactly what was queued and never read.
func TestMorphedConnCloseReportsUndelivered(t *testing.T) {
	old := pacerCloseTimeout
	pacerCloseTimeout = 200 * time.Millisecond
	t.Cleanup(func() { pacerCloseTimeout = old })

	profile := &TrafficProfile{Name: "T", PacketSizes: []int{1200}, PacketSizeProbs: []float64{1.0}}
	cases := []struct {
		name      string
		delay     time.Duration
		readFirst int
	}{
		// The pacer is blocked in a write when Close comes.
		{"unpaced, peer reads nothing", 0, 0},
		{"unpaced, peer reads 20000 bytes then stops", 0, 20000},
		// The pacer sleeps out the 50 ms after the one frame the peer
		// reads, so Close finds the rest still queued and the drain is
		// the one that blocks.
		{"paced, peer reads one frame then stops", pacerMaxDelay, morphHeaderLen + 1200},
	}
	for _, tc := range cases {
		readFirst := tc.readFirst
		t.Run(tc.name, func(t *testing.T) {
			sh := &chunkShaper{constShaper{delay: tc.delay}}
			client, server, cleanup := NewTestMorphedConnPair(profile, sh, &chunkShaper{})
			defer cleanup()

			// Read raw wire bytes, so the count compares with Stats.
			readDone := make(chan int, 1)
			go func() {
				n, _ := io.ReadFull(server.Conn, make([]byte, readFirst))
				readDone <- n
			}()
			// Well under the queue capacity: Write only enqueues and returns.
			if _, err := client.Write(closeTestPayload(128 << 10)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			read := <-readDone
			sent, _, _, _ := client.Stats()

			closed := make(chan error, 1)
			start := time.Now()
			go func() { closed <- client.Close() }()
			var err error
			select {
			case err = <-closed:
			case <-time.After(10 * time.Second):
				t.Fatal("Close did not return with a peer that does not read")
			}
			if took := time.Since(start); took > pacerCloseTimeout+2*time.Second {
				t.Errorf("Close took %v, the bound is %v", took, pacerCloseTimeout)
			}
			if !errors.Is(err, ErrShaperCloseIncomplete) {
				t.Fatalf("Close = %v, want ErrShaperCloseIncomplete", err)
			}
			if want := fmt.Sprintf("%d bytes of queued frames not written", sent-int64(read)); !strings.Contains(err.Error(), want) {
				t.Fatalf("Close = %q, want it to report %q (%d queued, %d read)", err, want, sent, read)
			}
		})
	}
}

// TestPacerCloseKeepsFramesAcceptedDuringClose: a frame enqueue accepts
// while close is running must still be written. The old drain stopped at
// the first empty look at the queue, and a producer racing it could put a
// frame in after that: Write returned nil and the frame was never written.
// This is the race as it happens, red on the old code within the 200
// rounds; TestPacerCloseWaitsForProducerMidSend pins it down
// deterministically.
func TestPacerCloseKeepsFramesAcceptedDuringClose(t *testing.T) {
	for range 200 {
		c := &countingConn{}
		p := newWritePacer(c, &constShaper{delay: 0})

		var accepted atomic.Int64
		var wg sync.WaitGroup
		started := make(chan struct{})
		for i := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; ; k++ {
					if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
						return
					}
					accepted.Add(1)
					if i == 0 && k == 16 {
						close(started)
					}
				}
			}()
		}
		<-started
		p.close()
		wg.Wait()

		c.mu.Lock()
		written := c.bytes
		c.mu.Unlock()
		if got := accepted.Load(); written != got {
			t.Fatalf("enqueue accepted %d frames, %d reached the conn", got, written)
		}
	}
}

// TestPacerCloseCountsFramesQueuedAfterWriteError: once a write fails the
// pacer goroutine releases what is queued and exits, but a producer that
// checked errSeen just before the failure can still put a frame in. close
// must count that frame as lost too, not leave it in the queue unreported.
func TestPacerCloseCountsFramesQueuedAfterWriteError(t *testing.T) {
	c := &countingConn{}
	c.failNext.Store(true)
	p := newWritePacer(c, &constShaper{delay: 0})
	if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); p.errSeen.Load() == nil; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the failed write was never recorded")
		}
	}
	// Let the goroutine finish its own release and exit, then queue a frame
	// the way the racing producer would, past the errSeen check.
	time.Sleep(50 * time.Millisecond)
	p.queue <- pacedFrame{packet: []byte{0, 0}, bucket: -1}

	err := p.close()
	if !errors.Is(err, ErrShaperCloseIncomplete) || !errors.Is(err, errFakeWrite) {
		t.Fatalf("close = %v, want ErrShaperCloseIncomplete wrapping the write error", err)
	}
	if !strings.Contains(err.Error(), "3 bytes of queued frames not written") {
		t.Fatalf("close = %q, want the failed frame and the late one counted (3 bytes)", err)
	}
}

// TestPacerCloseWaitsForProducerMidSend holds a producer inside enqueue,
// past its closed check, while close runs: the drain must not give up on
// the empty queue, and the frame the producer then sends must be written.
// After close, enqueue must refuse: on the old code its select could pick
// the free queue over done, and Write returned nil for a frame no one
// would ever write.
func TestPacerCloseWaitsForProducerMidSend(t *testing.T) {
	c := &countingConn{}
	p := newWritePacer(c, &constShaper{delay: 0})

	p.sendMu.RLock()
	closed := make(chan error, 1)
	go func() { closed <- p.close() }()
	<-p.done
	// Long enough for a drain that stops at an empty queue to have stopped.
	time.Sleep(50 * time.Millisecond)
	p.queue <- pacedFrame{packet: []byte{7}, bucket: -1}
	p.sendMu.RUnlock()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close = %v, want nil: the frame was sent before the queue closed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("close did not return")
	}
	if got := c.Writes(); got != 1 {
		t.Fatalf("%d writes, want the producer's frame written", got)
	}
	for i := range 100 {
		if err := p.enqueue(pacedFrame{packet: []byte{0}, bucket: -1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("enqueue %d after close = %v, want net.ErrClosed", i, err)
		}
	}
}
