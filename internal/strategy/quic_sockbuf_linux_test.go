package strategy

import (
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/quic-go/quic-go"
)

// quicGoDesiredBuf is what quic-go asks for (desiredBufferSize, 7 MiB).
const quicGoDesiredBuf = 7 << 20

func readSysctlInt(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cannot read %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return n
}

func sockBufs(t *testing.T, c *net.UDPConn) (rcv, snd int) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		rcv, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if gerr == nil {
			snd, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return rcv, snd
}

// TestQUICListenerSizesWrappedSocket starts a real quic-go listener on each of
// the server's packet-conn wrappers and reads the UDP socket's buffers back
// from the kernel. Before the wrappers forwarded SetReadBuffer/SetWriteBuffer,
// quic-go could not reach the socket and both stayed at the start value.
func TestQUICListenerSizesWrappedSocket(t *testing.T) {
	rmemMax := readSysctlInt(t, "/proc/sys/net/core/rmem_max")
	wmemMax := readSysctlInt(t, "/proc/sys/net/core/wmem_max")
	// The kernel doubles the request and clamps it to the ceiling first.
	wantRcv, wantSnd := 2*min(quicGoDesiredBuf, rmemMax), 2*min(quicGoDesiredBuf, wmemMax)

	for _, mode := range []struct {
		name string
		sni  bool
	}{{"salamander", false}, {"sni-reassembly", true}} {
		t.Run(mode.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			// Start well below anything quic-go would settle for, so a
			// listener that never reaches the socket is visible.
			if err := udp.SetReadBuffer(4096); err != nil {
				t.Fatal(err)
			}
			if err := udp.SetWriteBuffer(4096); err != nil {
				t.Fatal(err)
			}
			rcv0, snd0 := sockBufs(t, udp)
			if rcv0 >= wantRcv || snd0 >= wantSnd {
				t.Fatalf("start buffers %d/%d already at the target %d/%d; the test cannot see a change", rcv0, snd0, wantRcv, wantSnd)
			}

			s := NewQUICServer(QUICServerConfig{Secret: []byte("sockbuf-test"), SNIFragmentReassembly: mode.sni})
			wrapped := s.wrapPacketConn(udp)
			if _, ok := wrapped.(syscall.Conn); ok {
				t.Fatalf("%T exposes SyscallConn; quic-go would set DF and run path MTU discovery on it", wrapped)
			}
			tr := &quic.Transport{Conn: wrapped}
			ln, err := tr.Listen(&tls.Config{NextProtos: []string{"h3"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			defer ln.Close()

			rcv, snd := sockBufs(t, udp)
			if rcv != wantRcv || snd != wantSnd {
				t.Fatalf("after quic-go listen: SO_RCVBUF %d SO_SNDBUF %d, want %d %d (start %d %d)", rcv, snd, wantRcv, wantSnd, rcv0, snd0)
			}
		})
	}
}
