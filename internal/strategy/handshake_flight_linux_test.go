package strategy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// The ACK gate of a held attempt (handshakeProgressed) counted any
// acknowledged byte as progress. Seqovl opens with a decoy, which the
// server's TCP acknowledged while the censor dropped the ClientHello
// behind it: held past its share, Seqovl kept the rest of every cycle, and
// on the stand (r9-rx_hs_ab, fix17 and fix18) Geneva came up in the fifth
// cycle instead of the second, 76 s after the cut instead of 24. Progress
// is now the whole flight acknowledged, nothing left in flight or unsent.

// standCutRule is the stand's ClientHello cut: a TCP segment that starts a
// TLS handshake record longer than 1500 bytes is dropped on the way in.
const standCutRule = `table inet cut {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		meta l4proto tcp @ih,0,16 0x1603 @ih,24,16 > 0x5dc drop
	}
}
`

// underStandCut runs the calling test again in a network namespace of its
// own with the stand's cut on loopback, and reports whether the caller is
// that run. The outer run skips where a namespace can't be made.
func underStandCut(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TIREDVPN_STAND_CUT") == "1" {
		return true
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("no unprivileged network namespace here: %v", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft here")
	}
	script := `ip link set lo up && nft -f - && exec "$0" -test.run "^$1\$" -test.v`
	cmd := exec.Command("unshare", "-rn", "sh", "-c", script, os.Args[0], t.Name())
	cmd.Env = append(os.Environ(), "TIREDVPN_STAND_CUT=1")
	cmd.Stdin = strings.NewReader(standCutRule)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("under the stand's cut: %v\n%s", err, out)
	}
	t.Logf("under the stand's cut:\n%s", lastLines(out, 8))
	return false
}

func lastLines(b []byte, n int) string {
	lines := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			lines++
			if lines > n {
				return string(b[i+1:])
			}
		}
	}
	return string(b)
}

// silentServer accepts and reads everything, answering nothing: a server
// whose TCP acknowledges what reaches it.
func silentServer(t *testing.T, bind string) string {
	t.Helper()
	return readingServer(t, bind, false)
}

// readingServer is silentServer that, with greet, speaks first - one byte,
// which a greeting transport such as the test's Geneva waits for.
func readingServer(t *testing.T, bind string, greet bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if greet {
					_, _ = c.Write([]byte{'x'})
				}
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// clientHelloRecord is a TLS handshake record of 2076 bytes, as REALITY's
// ClientHello was on the stand.
func clientHelloRecord() []byte {
	rec := make([]byte, 2076)
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	rec[3], rec[4] = 0x08, 0x17
	return rec
}

// writeLikeSeqovl writes a decoy, then the record in two writes, its first
// fragment on its own, as Seqovl and REALITY write them.
func writeLikeSeqovl(c net.Conn) error {
	rec := clientHelloRecord()
	for _, p := range [][]byte{make([]byte, 100), rec[:130], rec[130:]} {
		if _, err := c.Write(p); err != nil {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// TestAFlightWithItsClientHelloDroppedHasNotProgressed: the decoy is
// acknowledged, the ClientHello is not; the flight has not got through.
func TestAFlightWithItsClientHelloDroppedHasNotProgressed(t *testing.T) {
	if !underStandCut(t) {
		return
	}
	c, err := net.Dial("tcp", silentServer(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := writeLikeSeqovl(c); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if handshakeProgressed(c) {
		t.Fatal("a flight whose ClientHello the route dropped counts as through, because its decoy was acknowledged")
	}
}

// TestAWholeFlightAcknowledgedHasProgressed: the same flight to a server
// that is slow to answer, with no cut; it has got through. And a conn with
// nothing written but its SYN has not.
func TestAWholeFlightAcknowledgedHasProgressed(t *testing.T) {
	addr := silentServer(t, "127.0.0.1:0")
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := writeLikeSeqovl(c); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !handshakeProgressed(c) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !handshakeProgressed(c) {
		t.Fatal("a whole flight acknowledged by a slow server does not count as through")
	}
	if handshakeProgressed(idle) {
		t.Fatal("a conn with only its SYN acknowledged counts as through")
	}
}

// decoyGreeter is Seqovl to the gate: it reports its TCP connect, writes a
// decoy and a ClientHello, and waits for an answer that never comes.
type decoyGreeter struct {
	id       string
	priority int
}

func (s *decoyGreeter) Name() string                        { return s.id }
func (s *decoyGreeter) ID() string                          { return s.id }
func (s *decoyGreeter) Priority() int                       { return s.priority }
func (s *decoyGreeter) RequiresServer() bool                { return true }
func (s *decoyGreeter) Description() string                 { return "decoy, then a ClientHello" }
func (s *decoyGreeter) Probe(context.Context, string) error { return nil }
func (*decoyGreeter) reportsTCPConnect()                    {}

func (s *decoyGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	conn, err := (&protect.ProtectDialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeLikeSeqovl(conn); err != nil {
		return nil, err
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestUnderTheStandsCutGenevaComesUpInTheSecondCycle is the stand case
// at test scale (TestARouteCuttingLargeClientHellosLetsGenevaInSoon, with
// the real cut on loopback and Seqovl writing what it writes): the second
// cycle, the first under pressure, reaches Geneva. Before, the held Seqovl
// kept it.
func TestUnderTheStandsCutGenevaComesUpInTheSecondCycle(t *testing.T) {
	if !underStandCut(t) {
		return
	}
	a6, a4 := readingServer(t, "[::1]:0", true), readingServer(t, "127.0.0.1:0", true)
	b6, b4 := readingServer(t, "[::1]:0", true), readingServer(t, "127.0.0.1:0", true)
	clk := newEndpointClock()
	m := dualStackPool(t, 3*time.Second, clk, [2]string{a6, a4}, [2]string{b6, b4})
	reality := &decoyGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&decoyGreeter{id: "polling", priority: 6})
	m.Register(&decoyGreeter{id: "stego", priority: 7})
	m.Register(&decoyGreeter{id: "seqovl", priority: 7})
	m.Register(&quietDialer{id: "ws", priority: 8})
	m.Register(&slowAnswer{greetingStrategy: greetingStrategy{id: "geneva", priority: 12}, after: 30 * time.Millisecond})
	markConnected(m, reality)

	backoff := time.Second
	for cycle := 1; cycle <= 6; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		conn, s, err := m.Connect(ctx, "")
		cancel()
		if err == nil {
			conn.Close()
			if s.ID() != "geneva" {
				t.Fatalf("connected via %s", s.ID())
			}
			if cycle > 2 {
				t.Fatalf("Geneva only in cycle %d", cycle)
			}
			fmt.Printf("Geneva in cycle %d\n", cycle)
			return
		}
		t.Logf("cycle %d on %s: %v", cycle, m.GetServerAddr(context.Background()), err)
		clk.Advance(15*time.Second + backoff)
		backoff = min(2*backoff, 30*time.Second)
	}
	t.Fatal("no Geneva in 6 cycles")
}

// TestAFlightStuckBehindAClosedWindowHasNotProgressed: a server that takes
// the first bytes and then stops reading; what is left of the flight sits
// unsent behind its closed window, and the flight has not got through.
func TestAFlightStuckBehindAClosedWindowHasNotProgressed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	held := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			held <- c // never read
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := <-held
	defer srv.Close()
	go func() { _, _ = c.Write(make([]byte, 64<<20)) }()
	time.Sleep(500 * time.Millisecond)
	if handshakeProgressed(c) {
		t.Fatal("a flight stuck behind a closed window counts as through")
	}
}
