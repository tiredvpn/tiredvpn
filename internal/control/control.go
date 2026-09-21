// Package control implements the unified control channel protocol for TiredVPN.
// Control messages are multiplexed with data using a 0xCC magic byte prefix.
package control

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Message types
const (
	MsgPing      byte = 0x01 // Keepalive request (client -> server)
	MsgPong      byte = 0x02 // Keepalive response (server -> client)
	MsgStatsReq  byte = 0x03 // Request stats
	MsgStatsResp byte = 0x04 // Stats response
)

// Magic byte to identify control messages
const ControlMagic byte = 0xCC

// MinMessageSize is the minimum size of a control message header
const MinMessageSize = 5 // magic + type + seq + length(2)

// MaxPayloadSize is the largest payload the wire format can carry. The length
// field is a uint16, so anything past this cannot be encoded without truncation.
const MaxPayloadSize = 0xFFFF // 65535

// Message represents a control channel message
type Message struct {
	Type    byte
	Seq     byte
	Payload []byte
}

// Serialize converts message to wire format. It returns an error when the
// payload is larger than MaxPayloadSize: the wire length field is a uint16, so
// a bigger payload would truncate the header silently and ParseMessage would
// then read garbage. All current call-sites send empty or tiny control
// payloads, so the error never fires in practice - but the guard turns a silent
// corruption into a hard failure if that ever changes.
func (m *Message) Serialize() ([]byte, error) {
	length := len(m.Payload)
	if length > MaxPayloadSize {
		return nil, fmt.Errorf("control: payload %d bytes exceeds max %d", length, MaxPayloadSize)
	}
	buf := make([]byte, MinMessageSize+length)
	buf[0] = ControlMagic
	buf[1] = m.Type
	buf[2] = m.Seq
	binary.BigEndian.PutUint16(buf[3:5], uint16(length))
	if length > 0 {
		copy(buf[5:], m.Payload)
	}
	return buf, nil
}

// ParseMessage parses a control message from wire format
// Returns nil if not a control message (doesn't start with ControlMagic)
func ParseMessage(data []byte) *Message {
	if len(data) < MinMessageSize {
		return nil
	}
	if data[0] != ControlMagic {
		return nil
	}

	length := binary.BigEndian.Uint16(data[3:5])
	if len(data) < MinMessageSize+int(length) {
		return nil
	}

	msg := &Message{
		Type: data[1],
		Seq:  data[2],
	}
	if length > 0 {
		// int(length) matters: 5+length in uint16 space overflows at the
		// ceiling (5+65535 wraps to 4), which would slice data[5:4] and panic.
		msg.Payload = make([]byte, length)
		copy(msg.Payload, data[5:5+int(length)])
	}
	return msg
}

// IsControlMessage checks if data starts with control magic byte
func IsControlMessage(data []byte) bool {
	return len(data) > 0 && data[0] == ControlMagic
}

// HandleServerMessage processes control messages on the server side
// This is a stateless handler that just echoes PONGs
func HandleServerMessage(conn net.Conn, data []byte) bool {
	msg := ParseMessage(data)
	if msg == nil {
		return false
	}

	switch msg.Type {
	case MsgPing:
		// Echo back PONG with same seq
		pong := &Message{
			Type: MsgPong,
			Seq:  msg.Seq,
		}
		wire, err := pong.Serialize()
		if err != nil {
			// Unreachable: PONG carries no payload. Guard defensively so a
			// future payload-bearing reply can never write a corrupt frame.
			log.Debug("Server: failed to serialize PONG seq=%d: %v", msg.Seq, err)
			return true
		}
		conn.Write(wire)
		log.Debug("Server: PING->PONG seq=%d", msg.Seq)

	case MsgStatsReq:
		// Server could send stats here if needed
		log.Debug("Server: Received STATS_REQ")

	default:
		log.Debug("Server: Unknown control message type: 0x%02x", msg.Type)
	}

	return true
}
