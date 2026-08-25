package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func addr(s string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(s), Port: 40000} }

func TestSourceReputation(t *testing.T) {
	t.Parallel()

	r := newSourceReputation(time.Hour)
	now := time.Now()

	if r.known(addr("203.0.113.7"), now) {
		t.Fatal("an address nobody has seen came back known")
	}

	r.remember(addr("203.0.113.7"), now)
	if !r.known(addr("203.0.113.7"), now) {
		t.Fatal("an address that just authenticated came back unknown")
	}

	// The port changes on every connection, so the vouching is per host.
	if !r.known(&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51515}, now) {
		t.Fatal("the same host on another port came back unknown")
	}
	if r.known(addr("203.0.113.8"), now) {
		t.Fatal("a different host inherited the reputation")
	}
	if r.known(addr("203.0.113.7"), now.Add(time.Hour+time.Minute)) {
		t.Fatal("reputation outlived its TTL")
	}
}

// TestShouldMirror is the decision the whole design rests on: probers get a
// donor, users do not.
func TestShouldMirror(t *testing.T) {
	t.Parallel()

	now := time.Now()
	user := addr("198.51.100.10")
	prober := addr("198.51.100.99")
	reputation.remember(user, now)

	tests := []struct {
		mode   string
		remote net.Addr
		want   bool
	}{
		{MirrorOff, prober, false},
		{MirrorOff, user, false},
		{MirrorAdaptive, prober, true},
		{MirrorAdaptive, user, false},
		{MirrorAlways, prober, true},
		{MirrorAlways, user, true},
	}
	for _, tt := range tests {
		if got := shouldMirror(tt.mode, tt.remote, now); got != tt.want {
			t.Errorf("shouldMirror(%s, %v) = %v, want %v", tt.mode, tt.remote, got, tt.want)
		}
	}
}

// TestMirrorPreservesWriteBoundaries is the byte-for-byte criterion, including
// fragmentation. A ClientHello arriving in three segments has to leave in three
// writes: a fallback that reassembles and re-sends is distinguishable from a
// direct connection by its framing alone, before anyone looks at the contents.
func TestMirrorPreservesWriteBoundaries(t *testing.T) {
	t.Parallel()

	fragments := [][]byte{
		[]byte("\x16\x03\x01\x00\x30first-"),
		[]byte("second-fragment-"),
		[]byte("third"),
	}

	clientSide, serverSide := net.Pipe()
	donorSide, donorPeer := net.Pipe()

	m := newMirrorConn(serverSide)
	m.attach(donorSide)

	go func() {
		for _, f := range fragments {
			_, _ = clientSide.Write(f)
			time.Sleep(5 * time.Millisecond)
		}
		_ = clientSide.Close()
	}()

	// Read the way the peek path does, and record what the donor saw per write.
	seen := make(chan []byte, len(fragments))
	go func() {
		buf := make([]byte, 512)
		for {
			n, err := donorPeer.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				seen <- chunk
			}
			if err != nil {
				close(seen)
				return
			}
		}
	}()

	buf := make([]byte, 512)
	for range fragments {
		if _, err := m.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	_ = serverSide.Close()
	_ = donorSide.Close()

	var got [][]byte
	for chunk := range seen {
		got = append(got, chunk)
	}
	if len(got) != len(fragments) {
		t.Fatalf("donor saw %d writes, client sent %d: fragmentation was not preserved", len(got), len(fragments))
	}
	for i := range fragments {
		if !bytes.Equal(got[i], fragments[i]) {
			t.Fatalf("write %d: donor got %q, client sent %q", i, got[i], fragments[i])
		}
	}
}

// TestMirrorReplaysWhatArrivedBeforeTheDial covers the window the eager dial
// leaves open: bytes read while the donor connection is still being established
// must reach it afterwards, in order and still in their own pieces.
func TestMirrorReplaysWhatArrivedBeforeTheDial(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	donorSide, donorPeer := net.Pipe()

	m := newMirrorConn(serverSide)

	go func() {
		_, _ = clientSide.Write([]byte("early-"))
		_, _ = clientSide.Write([]byte("bytes"))
	}()

	buf := make([]byte, 64)
	for range 2 {
		if _, err := m.Read(buf); err != nil {
			t.Fatal(err)
		}
	}

	// Donor arrives late.
	collected := make(chan []byte, 1)
	go func() {
		out := make([]byte, 0, 16)
		b := make([]byte, 64)
		for len(out) < len("early-bytes") {
			n, err := donorPeer.Read(b)
			out = append(out, b[:n]...)
			if err != nil {
				break
			}
		}
		collected <- out
	}()
	m.attach(donorSide)

	select {
	case got := <-collected:
		if string(got) != "early-bytes" {
			t.Fatalf("donor received %q, want the bytes read before it was attached", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the donor never received what was read before the dial finished")
	}
}

// TestMirrorStopReleasesTheDonor checks the authenticated path: once the gate
// says yes, nothing more is mirrored and the donor connection is handed back to
// be closed.
func TestMirrorStopReleasesTheDonor(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	donorSide, donorPeer := net.Pipe()

	m := newMirrorConn(serverSide)
	m.attach(donorSide)

	if got := m.stop(); got != donorSide {
		t.Fatal("stop did not hand back the donor connection")
	}

	// Anything read after the stop stays between us and the client.
	go func() { _, _ = clientSide.Write([]byte("after-the-verdict")) }()
	buf := make([]byte, 64)
	if _, err := m.Read(buf); err != nil {
		t.Fatal(err)
	}

	_ = donorPeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := donorPeer.Read(buf); err == nil && n > 0 {
		t.Fatalf("donor received %q after mirroring stopped", buf[:n])
	}
}

// TestMirrorAttachAfterStopClosesTheDonor covers the race the eager dial
// creates directly: the gate can finish before the dial does, and the
// connection that arrives late must be closed rather than leaked.
func TestMirrorAttachAfterStopClosesTheDonor(t *testing.T) {
	t.Parallel()

	_, serverSide := net.Pipe()
	donorSide, donorPeer := net.Pipe()

	m := newMirrorConn(serverSide)
	m.stop()
	m.attach(donorSide)

	// A closed pipe fails its next read immediately.
	_ = donorPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := donorPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("a donor attached after the stop was left open")
	}
}

// TestMirrorUnderRace is the criterion the task states outright: a thousand
// connections, no byte duplicated and none lost. The mirror runs a read
// goroutine against a dialer goroutine attaching the target, which is exactly
// where the reference implementation collected its bug fixes.
func TestMirrorUnderRace(t *testing.T) {
	if testing.Short() {
		t.Skip("1000 connections, skipped under -short")
	}
	t.Parallel()

	const conns = 1000
	payload := make([]byte, 96)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	failures := make(chan string, conns)

	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			clientSide, serverSide := net.Pipe()
			donorSide, donorPeer := net.Pipe()

			m := newMirrorConn(serverSide)

			// The dial finishes at an unpredictable moment relative to the
			// reads, which is the whole point of the exercise.
			go func() {
				if i%3 == 0 {
					time.Sleep(time.Duration(i%5) * time.Millisecond)
				}
				m.attach(donorSide)
			}()

			go func() {
				_, _ = clientSide.Write(payload)
				_ = clientSide.Close()
			}()

			got := make(chan []byte, 1)
			go func() {
				out := make([]byte, 0, len(payload))
				b := make([]byte, 64)
				_ = donorPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
				for len(out) < len(payload) {
					n, err := donorPeer.Read(b)
					out = append(out, b[:n]...)
					if err != nil {
						break
					}
				}
				got <- out
			}()

			buf := make([]byte, 64)
			for {
				if _, err := m.Read(buf); err != nil {
					break
				}
			}

			mirrored := <-got
			if !bytes.Equal(mirrored, payload) {
				failures <- fmt.Sprintf("connection mirrored %d bytes, sent %d", len(mirrored), len(payload))
			}
			_ = donorSide.Close()
			_ = serverSide.Close()
		}(i)
	}

	wg.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
}

// TestAwaitDonorPrefersTheEagerDial checks the two ways a donor arrives, and
// that the lazy path is what an already-trusted source falls back to.
func TestAwaitDonorPrefersTheEagerDial(t *testing.T) {
	t.Parallel()

	t.Run("eager result is taken as is", func(t *testing.T) {
		_, donorSide := net.Pipe()
		ch := make(chan donorHandoff, 1)
		ch <- donorHandoff{conn: donorSide, dest: "yandex.ru"}

		got, dest, err := awaitDonor(ch, nil, &serverContext{cfg: &Config{}})
		if err != nil || got != donorSide || dest != "yandex.ru" {
			t.Fatalf("got %v %q %v", got, dest, err)
		}
	})

	t.Run("eager failure is reported, not retried", func(t *testing.T) {
		ch := make(chan donorHandoff, 1)
		ch <- donorHandoff{dest: "yandex.ru", err: errors.New("connection refused")}

		if _, _, err := awaitDonor(ch, nil, &serverContext{cfg: &Config{}}); err == nil {
			t.Fatal("a failed eager dial was silently retried")
		}
	})

	t.Run("no donor without a destination", func(t *testing.T) {
		hello := buildRecordWithSNI(t, "attacker-controlled.example")
		_, _, err := awaitDonor(nil, hello, &serverContext{cfg: &Config{}})
		if !errors.Is(err, errNoDonor) {
			t.Fatalf("err = %v, want errNoDonor", err)
		}
	})
}

// TestDonorDialCountersSplit checks the metric that tells whether the adaptive
// policy is doing its job: donor traffic should track probing, not users.
func TestDonorDialCountersSplit(t *testing.T) {
	eagerBefore := realityDonorDialsEager.Load()
	lazyBefore := realityDonorDialsLazy.Load()

	// A destination that resolves nowhere: the dial fails, but it happened, and
	// that is what the counter is for.
	hello := buildRecordWithSNI(t, "yandex.ru")
	srvCtx := &serverContext{cfg: &Config{}}
	<-dialDonorEagerly(hello, srvCtx)

	if realityDonorDialsEager.Load() != eagerBefore+1 {
		t.Fatal("the eager counter did not move")
	}
	if realityDonorDialsLazy.Load() != lazyBefore {
		t.Fatal("an eager dial moved the lazy counter")
	}

	var sb testWriter
	writeREALITYDonorMetrics(&sb)
	for _, want := range []string{`when="eager"`, `when="lazy"`, "reality_donor_dials_total"} {
		if !sb.contains(want) {
			t.Fatalf("metrics output is missing %q:\n%s", want, sb.String())
		}
	}
}

// TestProxyBothWaysHalfClosePassesFIN states the half-close requirement from
// the client's side: a FIN must become a CloseWrite on the donor, not a full
// teardown, and the donor's reply must keep flowing afterwards.
func TestProxyBothWaysHalfClosePassesFIN(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A stand-in donor: reads to EOF, then answers. If the FIN arrived as a
	// full close, the answer would never get out.
	answered := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			answered <- err
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // returns on the client's FIN
		_, err = c.Write([]byte("donor still talking"))
		answered <- err
	}()

	donorConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	clientPipe, serverPipe := net.Pipe()
	go proxyBothWays(serverPipe, donorConn)

	go func() {
		_, _ = clientPipe.Write([]byte("hello"))
		_ = clientPipe.Close() // FIN towards the donor
	}()

	if err := <-answered; err != nil {
		t.Fatalf("the donor could not reply after the client's FIN: %v", err)
	}
}
