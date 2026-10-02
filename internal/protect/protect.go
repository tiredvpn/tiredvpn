//go:build android || linux

package protect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// The protect channel is a filesystem unix stream socket served by the
// Android app. One connection carries one request. Two wire protocols exist:
//
// Protocol 1 (every app up to 1.11.0): the core writes a descriptor number as
// 4 bytes little-endian, the app calls VpnService.protect(int) on that number
// and answers one byte, 0x00 ok, anything else failure. The app and the core
// share one process, so the number names the same descriptor table, and that
// is the weakness: a number is not a reference. If the app gets to it after
// the core has given up and the caller has closed the socket, the number may
// already belong to some other socket of the process, and that socket is what
// gets excluded from the VPN.
//
// Protocol 2 (opt-in with -protect-proto 2): no number on the wire. The core
// sends an 8-byte header with one SCM_RIGHTS descriptor attached to the same
// sendmsg, a duplicate of the socket. The app protects its own copy, closes
// it and answers 2 bytes, 0xA2 followed by a status. A late answer can only
// ever reach the right socket, because the app holds a reference to it.
//
// In protocol 1 the core narrows the race instead of closing it: it sends the
// number of a private duplicate and keeps that duplicate open until the app
// answers, until 30 s after the app hung up, or for 10 minutes at most. The
// caller's own descriptor no longer matters, the app only knows the number of
// the duplicate, and that number stays taken.
//
// On every failure the socket is shut down before the error is returned. A
// second reference (the held duplicate, or the app's copy) would otherwise
// keep the TCP connection open after the caller's close, which a peer could
// see as a FIN arriving late. shutdown(2) acts on the socket, not on the
// descriptor, so the FIN leaves when it always did.

// protectTimeout bounds every unix-socket round trip to the Android
// VpnService protect() handler. This is a purely local IPC call (LocalSocket
// on Android) that should complete in well under a second; the bound exists
// so a wedged/unresponsive VpnService side can never hang the caller forever.
//
// Every protect() call sits directly on the REALITY dial path (ProtectDialer
// wraps every TCP dial), so a stuck protect socket would otherwise block the
// JNI-triggered connect on Android with no deadline.
//
// Variables rather than constants so tests can shrink them.
var (
	protectTimeout = 5 * time.Second

	// v1HoldAfterEOF is how long a protocol-1 duplicate outlives the app
	// hanging up without an answer. The app may close the connection from
	// another thread while protect() is still running (service teardown, the
	// pre-API-29 read timeout), so EOF does not prove protect() has returned.
	v1HoldAfterEOF = 30 * time.Second

	// v1HoldMax caps how long a protocol-1 duplicate is held at all, counted
	// from the moment the request was sent.
	v1HoldMax = 10 * time.Minute

	// v1HoldLimit caps how many protocol-1 duplicates may be held at once.
	// Past it a request fails without being sent: closing a held number early
	// to make room would reopen the race.
	v1HoldLimit = 64
)

// Protocol 2 wire format.
var v2Magic = [4]byte{0x54, 0x56, 0x50, 0xF2} // "TVP" + 0xF2; as LE int32 it is negative

const (
	v2Version   = 0x02
	v2OpProtect = 0x01

	v2ReplyMarker = 0xA2

	v2StatusOK         = 0x00
	v2StatusProtectErr = 0x01
	v2StatusFdCount    = 0x02
	v2StatusBadRequest = 0x03
)

// Protocol versions accepted by SetProtocol.
const (
	ProtoV1 = 1
	ProtoV2 = 2
)

var (
	// configuredProto is what the app asked for with -protect-proto.
	configuredProto atomic.Int32
	// downgraded is set once an app answered a protocol-2 request in
	// protocol 1. It sticks for the life of the library: the app on the other
	// end does not change while the process lives.
	downgraded atomic.Bool
	// heldV1 counts protocol-1 duplicates currently held after a request.
	heldV1 atomic.Int32
)

// errV1Reply reports that the app answered a protocol-2 request in protocol 1.
var errV1Reply = errors.New("peer answered in protect protocol 1")

// SetProtocol selects the protect wire protocol requested by the app
// (-protect-proto). Anything but 2 means protocol 1.
func SetProtocol(v int) {
	if v != ProtoV2 {
		v = ProtoV1
	}
	configuredProto.Store(int32(v))
}

// Protocol returns the protect protocol in use: 2 when the app asked for it
// and has not answered in protocol 1 since, otherwise 1.
func Protocol() int { return effectiveProto() }

func effectiveProto() int {
	if configuredProto.Load() == ProtoV2 && !downgraded.Load() {
		return ProtoV2
	}
	return ProtoV1
}

// protector handles Android VpnService socket protection
type protector struct {
	path string
	mu   sync.Mutex
}

var globalProtector *protector

// InitAndroidProtector initializes the socket protector for Android
// Must be called before any network connections if running under VpnService
func InitAndroidProtector(socketPath string) error {
	if socketPath == "" {
		return nil // No protection needed
	}

	p := &protector{
		path: socketPath,
	}

	// Test connection to protect socket
	conn, err := net.DialTimeout("unix", socketPath, protectTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to protect socket %s: %w", socketPath, err)
	}
	conn.Close()

	globalProtector = p
	log.Info("Android socket protector initialized (path=%s, protocol=%d)", socketPath, effectiveProto())
	return nil
}

// ProtectSocket calls VpnService.protect() for the given file descriptor.
// The descriptor must stay open for the duration of the call; the protect
// channel never sees this number, only a duplicate of it.
func ProtectSocket(fd int) error {
	return ProtectRawFd(fd)
}

// ProtectConn protects a net.Conn's underlying socket.
//
// The whole exchange runs inside RawConn.Control, so the descriptor cannot be
// closed and its number handed out again while the request is in flight.
func ProtectConn(conn net.Conn) error {
	p := globalProtector
	if p == nil {
		return nil
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil // No fd to protect
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var perr error
	if err := rawConn.Control(func(fd uintptr) {
		perr = p.protect(int(fd))
	}); err != nil {
		return err
	}
	return perr
}

// getConnFd extracts the file descriptor from various connection types
func getConnFd(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return -1, nil // Can't get fd, but not an error
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	if err := rawConn.Control(func(fdRaw uintptr) {
		fd = int(fdRaw)
	}); err != nil {
		return -1, err
	}
	return fd, nil
}

// DialWithProtect creates a TCP connection and protects it from VPN routing
func DialWithProtect(network, address string) (net.Conn, error) {
	// Create socket
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Protect socket if running under VpnService
	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// ProtectDialer wraps a dialer with socket protection
type ProtectDialer struct {
	Dialer *net.Dialer
}

// Dial implements net.Dialer.Dial with socket protection
func (d *ProtectDialer) Dial(network, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// DialContext implements context-aware dialing with protection
func (d *ProtectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if err := ProtectConn(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("protect failed: %w", err)
	}

	return conn, nil
}

// IsProtectorActive returns whether the Android protector is active
func IsProtectorActive() bool {
	return globalProtector != nil
}

// ProtectRawFd protects the socket behind fd. The descriptor must stay open
// for the duration of the call; only a duplicate of it is ever handed to the
// app, in either protocol.
func ProtectRawFd(fd int) error {
	p := globalProtector
	if p == nil {
		return nil
	}
	return p.protect(fd)
}

// protect is the single path every entry point ends in. fd belongs to the
// caller and is valid for the whole call.
func (p *protector) protect(fd int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.roundTrip(fd)
	if err != nil {
		// The caller closes the socket on error, but a second reference may
		// outlive that close; see the package comment. ENOTCONN on an
		// unconnected UDP socket is expected and harmless.
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		return err
	}
	log.Debug("Socket fd=%d protected", fd)
	return nil
}

func (p *protector) roundTrip(fd int) error {
	if effectiveProto() == ProtoV2 {
		err := p.roundTripV2(fd)
		if !errors.Is(err, errV1Reply) {
			return err
		}
		if downgraded.CompareAndSwap(false, true) {
			log.Warn("protect: %v, switching to protocol 1 for the rest of the process", err)
		}
	}
	return p.roundTripV1(fd)
}

// dupFd returns a close-on-exec duplicate of fd.
func dupFd(fd int) (int, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("protect: dup fd %d: %w", fd, err)
	}
	return dup, nil
}

func (p *protector) dial() (*net.UnixConn, error) {
	conn, err := net.DialTimeout("unix", p.path, protectTimeout)
	if err != nil {
		return nil, fmt.Errorf("protect socket connect failed: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("protect socket is not a unix connection (%T)", conn)
	}
	return uc, nil
}

// roundTripV2 sends one protocol-2 request. The duplicate is closed right
// after sendmsg: from there on the message itself holds a reference to the
// socket, and the app gets its own descriptor for it.
func (p *protector) roundTripV2(fd int) error {
	dup, err := dupFd(fd)
	if err != nil {
		return err
	}
	conn, err := p.dial()
	if err != nil {
		unix.Close(dup)
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(protectTimeout))

	var req [8]byte
	copy(req[:4], v2Magic[:])
	req[4] = v2Version
	req[5] = v2OpProtect
	oob := unix.UnixRights(dup)
	n, oobn, err := conn.WriteMsgUnix(req[:], oob, nil)
	unix.Close(dup)
	if err != nil {
		return fmt.Errorf("protect v2 request write failed: %w", err)
	}
	if n != len(req) || oobn != len(oob) {
		return fmt.Errorf("protect v2 request short write (%d/%d bytes, %d/%d oob)", n, len(req), oobn, len(oob))
	}

	var reply [2]byte
	if _, err := conn.Read(reply[:1]); err != nil {
		return fmt.Errorf("protect v2 response read failed: %w", err)
	}
	switch reply[0] {
	case v2ReplyMarker:
	case 0x00, 0x01:
		return errV1Reply
	default:
		return fmt.Errorf("protect v2: unexpected response byte 0x%02x", reply[0])
	}
	if _, err := conn.Read(reply[1:]); err != nil {
		return fmt.Errorf("protect v2 response status read failed: %w", err)
	}
	switch reply[1] {
	case v2StatusOK:
		return nil
	case v2StatusProtectErr:
		return errors.New("protect failed: VpnService.protect returned false")
	case v2StatusFdCount:
		return errors.New("protect failed: app did not receive exactly one descriptor")
	case v2StatusBadRequest:
		return errors.New("protect failed: app rejected the request header")
	default:
		return fmt.Errorf("protect failed: unknown status 0x%02x", reply[1])
	}
}

// roundTripV1 sends one protocol-1 request carrying the number of a private
// duplicate, and keeps that duplicate open for as long as the app might still
// act on the number (see v1HoldAfterEOF, v1HoldMax).
func (p *protector) roundTripV1(fd int) error {
	if int(heldV1.Load()) >= v1HoldLimit {
		return fmt.Errorf("protect backlog: %d requests still unanswered", heldV1.Load())
	}
	dup, err := dupFd(fd)
	if err != nil {
		return err
	}
	conn, err := p.dial()
	if err != nil {
		unix.Close(dup)
		return err
	}
	conn.SetDeadline(time.Now().Add(protectTimeout))

	var req [4]byte
	binary.LittleEndian.PutUint32(req[:], uint32(dup))
	sentAt := time.Now()
	if n, err := conn.Write(req[:]); err != nil || n != len(req) {
		// The app needs all 4 bytes before it acts; a failed write of a
		// 4-byte request on a fresh unix socket delivered nothing usable.
		conn.Close()
		unix.Close(dup)
		return fmt.Errorf("fd write failed: %w", err)
	}

	var reply [1]byte
	n, err := conn.Read(reply[:])
	if err == nil && n == 1 {
		conn.Close()
		unix.Close(dup)
		if reply[0] != 0 {
			return fmt.Errorf("protect failed (response=%d)", reply[0])
		}
		return nil
	}

	nerr, ok := errors.AsType[net.Error](err)
	timedOut := ok && nerr.Timeout()
	holdV1(dup, conn, sentAt, !timedOut)
	return fmt.Errorf("protect response read failed: %w", err)
}

// holdV1 keeps dup open in the background until the app answers, until
// v1HoldAfterEOF after it hung up, or until v1HoldMax after sentAt. It owns
// dup and conn from here on.
func holdV1(dup int, conn *net.UnixConn, sentAt time.Time, hungUp bool) {
	holdMax, holdAfterEOF := v1HoldMax, v1HoldAfterEOF
	hardDeadline := sentAt.Add(holdMax)
	heldV1.Add(1)
	go func() {
		defer heldV1.Add(-1)
		defer unix.Close(dup)
		defer conn.Close()

		if !hungUp {
			conn.SetDeadline(hardDeadline)
			var reply [1]byte
			n, err := conn.Read(reply[:])
			if n == 1 {
				log.Debug("protect: late answer for held fd=%d (response=%d)", dup, reply[0])
				return
			}
			if nerr, ok := errors.AsType[net.Error](err); ok && nerr.Timeout() {
				log.Warn("protect: fd=%d unanswered for %v, releasing it", dup, holdMax)
				return
			}
		}
		if wait := min(holdAfterEOF, time.Until(hardDeadline)); wait > 0 {
			time.Sleep(wait)
		}
	}()
}
