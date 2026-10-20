package tun

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestLateFlagsByteNeverReachesTheStream: a v0x03 client gets a flags byte
// only when it is non-zero, and the reader gives up on it after
// handshakeFlagsGrace. When the byte comes later than that, the peek still in
// flight collects it after the reader has settled on a bare 9-byte answer.
// Handed to the packet loop it would shift every frame after it (issue #99),
// and with port hopping advertised the rest of the port-hop layout would
// follow it into the stream. The session fails instead, on every later Read
// too, and nothing of the answer comes out as data.
func TestLateFlagsByteNeverReachesTheStream(t *testing.T) {
	portHopV2 := []byte{
		tunFlagPortHopping | tunFlagMTUProbe,
		0x9c, 0x40, 0x9c, 0xa4, // ports 40000-40100
		0, 0, 0, 60, // hop interval
		0,       // strategy
		3,       // seed length
		1, 2, 3, // seed
	}
	for _, tc := range []struct {
		name string
		late []byte
	}{
		{"probe flag only", []byte{tunFlagMTUProbe}},
		{"port-hop layout", portHopV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			t.Cleanup(func() { cli.Close(); srv.Close() })
			go func() {
				if _, err := srv.Write(handshakeBase); err != nil {
					return
				}
				time.Sleep(handshakeFlagsGrace + 300*time.Millisecond)
				_, _ = srv.Write(append(append([]byte{}, tc.late...), firstFrame...))
			}()

			_, n, next, err := readHandshakeResponse(cli, tunHandshakeVersion, time.Now().Add(5*time.Second))
			if err != nil {
				t.Fatalf("readHandshakeResponse: %v", err)
			}
			if n != 9 {
				t.Fatalf("n = %d, want 9: the byte came after the grace", n)
			}

			for i := range 2 {
				type result struct {
					b   []byte
					err error
				}
				ch := make(chan result, 1)
				go func() {
					buf := make([]byte, 64)
					m, err := next.Read(buf)
					ch <- result{buf[:m], err}
				}()
				select {
				case r := <-ch:
					if !errors.Is(r.err, errLateHandshakeFlags) {
						t.Fatalf("read %d after the late flags byte = %x, %v; want errLateHandshakeFlags", i, r.b, r.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("read %d after the late flags byte did not return", i)
				}
			}
		})
	}
}
