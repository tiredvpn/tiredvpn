package strategy

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// TestAServerParkIsWarnedOnceAPark is the fix13c stand's log: while a server
// was parked, every SOCKS dial forced onto it failed, extended the park and
// logged "every address of the server has a verdict - parking the server" at
// Warn, about every four seconds. The park is news once, when it starts; the
// extensions go at Debug, and a park that ran out and comes back is news
// again. Driven through SessionEnded, a production entry, on a dual-stack
// server on a clock the test moves.
func TestAServerParkIsWarnedOnceAPark(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return out.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	warns := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for line := range strings.SplitSeq(out.String(), "\n") {
			if strings.Contains(line, "parking the server") && strings.Contains(line, "WRN") {
				n++
			}
		}
		return n
	}

	clk := newEndpointClock()
	a6, a4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	b6, b4 := newHelloListenerAt(t, "[::1]:0"), newHelloListener(t)
	m := dualStackPool(t, time.Second, clk, [2]string{a6.addr, a4.addr}, [2]string{b6.addr, b4.addr})
	sel := m.selector()
	c4, _ := sel.CandidateForAddr(a4.addr)
	c6, _ := sel.CandidateForAddr(a6.addr)
	dead := func(c endpoint.Candidate) {
		m.SessionEnded(SessionEnd{Strategy: "reality", Endpoint: c, HasEndpoint: true, Dead: true})
	}

	dead(c4)
	dead(c6)
	if !sel.IsParked(c4) || !sel.IsParked(c6) {
		t.Fatal("two dead sessions did not park the server - the test proves nothing")
	}
	if n := warns(); n != 1 {
		t.Fatalf("%d warnings for the park, want 1", n)
	}
	// The dials that follow while it is parked extend the park, quietly.
	for range 5 {
		clk.Advance(4 * time.Second)
		dead(c6)
	}
	if n := warns(); n != 1 {
		t.Fatalf("%d warnings after five dials into a parked server, want still 1", n)
	}
	// The park runs out and the server earns another one: news again.
	clk.Advance(2 * time.Hour)
	dead(c4)
	dead(c6)
	if n := warns(); n != 2 {
		t.Fatalf("%d warnings after a new park, want 2", n)
	}
}
