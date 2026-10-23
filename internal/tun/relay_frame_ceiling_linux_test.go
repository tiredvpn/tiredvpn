package tun

import (
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRelayRejectsFrameOverCeilingBeforeAllocating: the control-socket relay
// (the one the Android app runs on) read a frame header and handed any length
// over the MTU to handleOversizedPacket, which allocated the whole announced
// length and waited for it. A garbage or reset header of 0xffffffff was a
// 4 GiB allocation and a fatal out-of-memory on a phone. A length over the
// protocol ceiling must end the relay at once, without allocating it, the way
// VPNClient's read loop already does.
//
// The lengths tried are small enough that the old code survives them (it
// allocates and then blocks waiting for bytes that never come), so the test
// fails on the old code by timing out, not by taking the test binary down.
func TestRelayRejectsFrameOverCeilingBeforeAllocating(t *testing.T) {
	for _, announced := range []uint32{maxFrameLen + 1, 1 << 20} {
		ft := newFakeTun(t, false)
		dev, err := CreateTUNFromFd(ft.host, "", 1280)
		if err != nil {
			t.Fatal(err)
		}
		ft.host = -1 // owned by dev now
		var tunPtr atomic.Pointer[TUNDevice]
		tunPtr.Store(dev)

		cli, srv := net.Pipe()
		done := make(chan string, 1)
		stop := make(chan struct{})

		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		go func() {
			done <- runServerToTUN(stop, func() {}, &tunPtr, cli, net.IPv4(10, 9, 0, 1), func() {}, nil, nil)
		}()
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], announced)
		srv.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := srv.Write(hdr[:]); err != nil {
			t.Fatalf("write header: %v", err)
		}

		var reason string
		select {
		case reason = <-done:
		case <-time.After(3 * time.Second):
			close(stop)
			cli.Close()
			srv.Close()
			<-done
			dev.Close()
			t.Fatalf("length %d: relay still waiting for the frame's bytes after 3s instead of dropping the connection", announced)
		}
		runtime.ReadMemStats(&after)
		cli.Close()
		srv.Close()
		dev.Close()

		if !strings.Contains(reason, "over_ceiling") {
			t.Fatalf("length %d: relay ended with %q, want the over-ceiling reason", announced, reason)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew >= uint64(announced)/2 {
			t.Fatalf("length %d: relay allocated %d bytes for a frame it should have refused", announced, grew)
		}
	}
}

// TestRelayStillDropsOversizedPacketWithinCeiling: a length over the MTU but
// within the protocol ceiling is a real packet that is too big for this MTU.
// That path - read it, drop it, answer with ICMP Frag Needed, keep going - must
// survive the new check.
func TestRelayStillDropsOversizedPacketWithinCeiling(t *testing.T) {
	ft := newFakeTun(t, false)
	dev, err := CreateTUNFromFd(ft.host, "", 1280)
	if err != nil {
		t.Fatal(err)
	}
	ft.host = -1
	defer dev.Close()
	var tunPtr atomic.Pointer[TUNDevice]
	tunPtr.Store(dev)

	cli, srv := net.Pipe()
	defer srv.Close()
	done := make(chan string, 1)
	stop := make(chan struct{})
	go func() {
		done <- runServerToTUN(stop, func() {}, &tunPtr, cli, net.IPv4(10, 9, 0, 1), func() {}, nil, nil)
	}()

	const size = 1500 // over the 1280 MTU, well under the ceiling
	frame := make([]byte, 4+size)
	binary.BigEndian.PutUint32(frame[:4], size)
	frame[4] = 0x45
	srv.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := srv.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	select {
	case reason := <-done:
		t.Fatalf("relay ended on a %d-byte packet within the ceiling: %q", size, reason)
	case <-time.After(300 * time.Millisecond):
	}
	close(stop)
	cli.Close()
	<-done
}
