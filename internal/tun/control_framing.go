package tun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// maxControlMessage bounds one control message. Real commands are well under
// a hundred bytes; the limit only keeps a peer that never finishes a message
// from growing the buffer without end.
const maxControlMessage = 64 << 10

// errControlMessageTooLarge ends the connection: a peer that sends this much
// without completing a command is not a host the server can resync with.
var errControlMessageTooLarge = fmt.Errorf("control message larger than %d bytes", maxControlMessage)

// controlMsg is one command cut from the stream and the descriptor that was
// sent with it (-1 if none).
type controlMsg struct {
	data []byte
	fd   int
}

// controlFramer cuts the control socket's byte stream into JSON commands.
//
// The socket is SOCK_STREAM, so a read can carry several commands or part of
// one; the host's writes are not preserved as units. Each value is taken by
// a JSON decoder, so commands work with or without the "\n" the host puts
// after them. A line that is not valid JSON is skipped up to the next "\n"
// and the stream carries on: the commands before it have already run, the
// ones after it still do, and the connection - whose loss the host answers
// with a full core restart - stays up.
//
// Descriptors: the kernel ends a stream read right after the bytes that
// carried SCM_RIGHTS, and the host sends a command and its fd in one write.
// So the fd delivered by a read belongs to the last command that starts in
// that read - complete, or still incomplete at the end of the buffer, in
// which case it waits there for the rest of its command.
type controlFramer struct {
	buf    []byte
	tailFd int // fd of the incomplete command at the start of buf, -1 if none
}

func newControlFramer() *controlFramer {
	return &controlFramer{tailFd: -1}
}

type framedSpan struct {
	start, end int
	broken     bool
}

// feed adds one read and returns the commands it completed, in order. Every
// fd it receives ends up either attached to exactly one returned command,
// held for the incomplete command at the end, or closed here.
func (f *controlFramer) feed(data []byte, fd int) ([]controlMsg, error) {
	readStart := len(f.buf)
	f.buf = append(f.buf, data...)

	var spans []framedSpan
	tailStart := -1
	tooLarge := false
	off := 0
	for {
		for off < len(f.buf) && isJSONSpace(f.buf[off]) {
			off++
		}
		if off == len(f.buf) {
			break
		}
		dec := json.NewDecoder(bytes.NewReader(f.buf[off:]))
		var raw json.RawMessage
		err := dec.Decode(&raw)
		switch {
		case err == nil:
			end := off + int(dec.InputOffset())
			if end-off > maxControlMessage {
				// Complete, but too big to be a command; it also took that
				// much memory to get here, which is what the limit is for.
				spans = append(spans, framedSpan{start: off, end: end, broken: true})
				tooLarge = true
				off = end
				continue
			}
			spans = append(spans, framedSpan{start: off, end: end})
			off = end
			continue
		case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
			tailStart = off
		default:
			// Malformed. Nothing that arrives later can make it valid, so
			// drop it through the end of its line. Without a newline yet,
			// keep it until one comes (or the size limit trips).
			nl := bytes.IndexByte(f.buf[off:], '\n')
			if nl >= 0 {
				log.Warn("Control: skipping malformed command: %v (%q)", err, clip(f.buf[off:off+nl]))
				spans = append(spans, framedSpan{start: off, end: off + nl + 1, broken: true})
				off += nl + 1
				continue
			}
			tailStart = off
		}
		break
	}

	// Who gets this read's fd: the last command starting in this read.
	target := -1 // index into spans; len(spans) means the tail
	if fd >= 0 {
		if tailStart >= readStart {
			target = len(spans)
		} else {
			for i := len(spans) - 1; i >= 0; i-- {
				if spans[i].start >= readStart {
					target = i
					break
				}
			}
		}
		if target < 0 {
			log.Warn("Control: fd %d arrived with no command of its own, closing it", fd)
			releaseReceivedFd(fd)
		}
	}

	var msgs []controlMsg
	for i, sp := range spans {
		msgFd := -1
		if sp.start == 0 && f.tailFd >= 0 {
			// The command that was incomplete at the end of the last read.
			msgFd, f.tailFd = f.tailFd, -1
		}
		if i == target {
			if msgFd >= 0 {
				log.Warn("Control: second fd %d for one command, closing it", fd)
				releaseReceivedFd(fd)
			} else {
				msgFd = fd
			}
		}
		if sp.broken {
			releaseReceivedFd(msgFd)
			continue
		}
		msgs = append(msgs, controlMsg{data: append([]byte(nil), f.buf[sp.start:sp.end]...), fd: msgFd})
	}

	if tailStart < 0 {
		tailStart = len(f.buf)
	}
	if target == len(spans) {
		if tailStart == 0 && f.tailFd >= 0 {
			log.Warn("Control: second fd %d for one command, closing it", fd)
			releaseReceivedFd(fd)
		} else {
			f.tailFd = fd
		}
	}
	f.buf = append(f.buf[:0], f.buf[tailStart:]...)
	if tooLarge || len(f.buf) > maxControlMessage {
		return msgs, errControlMessageTooLarge
	}
	return msgs, nil
}

// release closes the fd still held for an incomplete command. Called when
// the connection ends.
func (f *controlFramer) release() {
	releaseReceivedFd(f.tailFd)
	f.tailFd = -1
	f.buf = nil
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func clip(b []byte) []byte {
	if len(b) > 80 {
		return b[:80]
	}
	return b
}
