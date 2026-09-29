//go:build linux

package ktls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// TLS_GET_RECORD_TYPE is the cmsg type under SOL_TLS that carries the content
// type of the record a recvmsg returned bytes from (linux/tls.h).
const tlsGetRecordType = 2

// TLS content types (RFC 8446, section 5.1).
const (
	recordTypeAlert           = 21
	recordTypeHandshake       = 22
	recordTypeApplicationData = 23
)

// TLS 1.3 post-handshake message types (RFC 8446, section 4).
const (
	msgTypeNewSessionTicket = 4
	msgTypeKeyUpdate        = 24
)

// recvState is what Read needs to deal with non-data records. With TLS_RX set,
// a plain read(2) that meets a record whose content type is not
// application_data fails with EIO. In TLS 1.3 the peer may send such records
// at any time after the handshake: a server sends NewSessionTicket right after
// its Finished, and the ticket can reach the socket after the handover. Read
// therefore uses recvmsg with room for the record-type cmsg, drops session
// tickets (they only enable resumption), turns close_notify into io.EOF and
// fails on anything it cannot follow, such as KeyUpdate.
type recvState struct {
	raw     syscall.RawConn
	recv    func(fd uintptr) bool // built once: a per-Read closure would allocate
	dst     []byte                // recvmsg arguments and results for recv
	n       int
	oobn    int
	flags   int
	rerr    error
	oob     []byte // cmsg buffer, heap-allocated so the Cmsghdr cast is aligned
	ctrl    []byte // bytes of a non-data record not yet fully parsed
	ctrlTyp byte
	scratch []byte
	err     error // sticky: set once the stream cannot continue
}

func (c *Conn) readSocket(b []byte) (int, error) {
	rx := &c.rx
	if rx.err != nil {
		return 0, rx.err
	}
	if rx.raw == nil {
		raw, err := c.tcpConn.SyscallConn()
		if err != nil {
			return 0, c.opError(err)
		}
		rx.raw = raw
		rx.oob = make([]byte, syscall.CmsgSpace(1))
		rx.recv = func(fd uintptr) bool {
			for {
				rx.n, rx.oobn, rx.flags, _, rx.rerr = syscall.Recvmsg(int(fd), rx.dst, rx.oob, 0)
				if rx.rerr != syscall.EINTR {
					return rx.rerr != syscall.EAGAIN
				}
			}
		}
	}
	for {
		// A handshake message may span records; its continuation is read
		// into scratch so the caller's buffer only ever receives data.
		dst := b
		if len(rx.ctrl) > 0 {
			if rx.scratch == nil {
				rx.scratch = make([]byte, maxCiphertextLen)
			}
			dst = rx.scratch
		}

		rx.dst = dst
		err := rx.raw.Read(rx.recv)
		rx.dst = nil
		if err == nil && rx.rerr != nil {
			err = os.NewSyscallError("read", rx.rerr)
		}
		if err != nil {
			return 0, c.opError(err)
		}
		n, oobn, flags := rx.n, rx.oobn, rx.flags
		if flags&syscall.MSG_CTRUNC != 0 {
			return 0, c.fail(errors.New("kTLS: record type control message truncated"))
		}
		if n == 0 {
			if len(rx.ctrl) > 0 {
				return 0, c.fail(io.ErrUnexpectedEOF)
			}
			return 0, io.EOF
		}

		typ := byte(recordTypeApplicationData) // no cmsg: plain TCP, not kTLS RX
		if oobn >= syscall.CmsgLen(1) {
			h := (*syscall.Cmsghdr)(unsafe.Pointer(&rx.oob[0]))
			if h.Level == SOL_TLS && h.Type == tlsGetRecordType {
				typ = rx.oob[syscall.CmsgLen(0)]
			}
		}
		if typ == recordTypeApplicationData {
			if len(rx.ctrl) > 0 {
				// RFC 8446 5.1: handshake messages are not interleaved with
				// other record types.
				return 0, c.fail(errors.New("kTLS: application data inside a handshake message"))
			}
			return n, nil
		}

		if len(rx.ctrl) > 0 && typ != rx.ctrlTyp {
			return 0, c.fail(fmt.Errorf("kTLS: record type %d inside a type %d message", typ, rx.ctrlTyp))
		}
		rx.ctrlTyp = typ
		rx.ctrl = append(rx.ctrl, dst[:n]...)
		if err := c.consumeControl(); err != nil {
			return 0, c.fail(err)
		}
	}
}

// consumeControl processes complete messages in rx.ctrl and keeps any
// incomplete remainder for the next record.
func (c *Conn) consumeControl() error {
	rx := &c.rx
	switch rx.ctrlTyp {
	case recordTypeAlert:
		if len(rx.ctrl) < 2 {
			return nil
		}
		if rx.ctrl[1] == 0 { // close_notify
			return io.EOF
		}
		return fmt.Errorf("kTLS: remote alert %d", rx.ctrl[1])
	case recordTypeHandshake:
		for len(rx.ctrl) >= 4 {
			n := 4 + (int(rx.ctrl[1])<<16 | int(rx.ctrl[2])<<8 | int(rx.ctrl[3]))
			if len(rx.ctrl) < n {
				return nil
			}
			switch rx.ctrl[0] {
			case msgTypeNewSessionTicket:
				// Dropped: it would only let a later connection resume.
			case msgTypeKeyUpdate:
				return errors.New("kTLS: peer sent KeyUpdate, which the kernel receive path cannot follow")
			default:
				return fmt.Errorf("kTLS: unexpected post-handshake message type %d", rx.ctrl[0])
			}
			rx.ctrl = rx.ctrl[n:]
		}
		if len(rx.ctrl) == 0 {
			rx.ctrl = nil
		}
		return nil
	default:
		return fmt.Errorf("kTLS: unexpected record type %d", rx.ctrlTyp)
	}
}

func (c *Conn) fail(err error) error {
	if !errors.Is(err, io.EOF) {
		err = c.opError(err)
	}
	c.rx.err = err
	return err
}

// opError gives socket errors the same shape net.TCPConn.Read produces, so
// callers matching on timeouts or net.ErrClosed see no difference.
func (c *Conn) opError(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) {
		err = oe.Err
	}
	return &net.OpError{Op: "read", Net: "tcp", Source: c.tcpConn.LocalAddr(), Addr: c.tcpConn.RemoteAddr(), Err: err}
}
