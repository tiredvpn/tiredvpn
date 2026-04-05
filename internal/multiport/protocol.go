package multiport

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// Protocol version
const (
	ProtocolVersion = 0x01
)

// Packet flags
const (
	FlagFIN  = 1 << 0 // 0x01 - Connection termination
	FlagACK  = 1 << 1 // 0x02 - Acknowledgment
	FlagDATA = 1 << 2 // 0x04 - Data packet
)

// Packet header size
const (
	HeaderSize    = 16 // Version(1) + Flags(1) + SessionID(2) + Seq(8) + PayloadLen(2) + Checksum(2)
	MaxPacketSize = 1400
	MaxPayload    = MaxPacketSize - HeaderSize
)

// Packet represents a UDP packet in the multiport protocol
// Wire format:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Version    |     Flags     |         Session ID            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// |                          (64-bit)                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Payload Length       |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                         Payload Data                          |
// |                         (variable)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Packet struct {
	Version   uint8
	Flags     uint8
	SessionID uint16
	Seq       uint64
	Payload   []byte
}

// Marshal serializes a packet into wire format
func (p *Packet) Marshal() ([]byte, error) {
	if len(p.Payload) > MaxPayload {
		return nil, fmt.Errorf("payload too large: %d > %d", len(p.Payload), MaxPayload)
	}

	buf := make([]byte, HeaderSize+len(p.Payload))

	// Header
	buf[0] = p.Version
	buf[1] = p.Flags
	binary.BigEndian.PutUint16(buf[2:4], p.SessionID)
	binary.BigEndian.PutUint64(buf[4:12], p.Seq)
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(p.Payload)))

	// Payload
	copy(buf[HeaderSize:], p.Payload)

	// Calculate checksum over entire packet (except checksum field itself)
	checksum := crc32.ChecksumIEEE(buf[:12])         // Header before checksum
	checksum ^= crc32.ChecksumIEEE(buf[HeaderSize:]) // Payload
	binary.BigEndian.PutUint16(buf[14:16], uint16(checksum&0xFFFF))

	return buf, nil
}

// Unmarshal deserializes a packet from wire format
func (p *Packet) Unmarshal(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("packet too short: %d < %d", len(data), HeaderSize)
	}

	// Parse header
	p.Version = data[0]
	p.Flags = data[1]
	p.SessionID = binary.BigEndian.Uint16(data[2:4])
	p.Seq = binary.BigEndian.Uint64(data[4:12])
	payloadLen := binary.BigEndian.Uint16(data[12:14])
	storedChecksum := binary.BigEndian.Uint16(data[14:16])

	if len(data) < HeaderSize+int(payloadLen) {
		return fmt.Errorf("packet truncated: expected %d, got %d", HeaderSize+payloadLen, len(data))
	}

	// Verify checksum
	expectedChecksum := crc32.ChecksumIEEE(data[:12])
	expectedChecksum ^= crc32.ChecksumIEEE(data[HeaderSize : HeaderSize+payloadLen])
	if uint16(expectedChecksum&0xFFFF) != storedChecksum {
		return fmt.Errorf("checksum mismatch: expected %04x, got %04x", expectedChecksum&0xFFFF, storedChecksum)
	}

	// Extract payload
	p.Payload = make([]byte, payloadLen)
	copy(p.Payload, data[HeaderSize:HeaderSize+payloadLen])

	return nil
}

// AckPacket represents a selective acknowledgment packet
// Wire format is similar to data packet but with ACK flag set and bitmap in payload
type AckPacket struct {
	Version   uint8
	Flags     uint8
	SessionID uint16
	AckBase   uint64 // Lowest unacknowledged sequence number
	AckBitmap []byte // Bitmap for selective ACK (256 bits = 32 bytes max)
}

// Marshal serializes an ACK packet
func (a *AckPacket) Marshal() ([]byte, error) {
	if len(a.AckBitmap) > 32 {
		return nil, fmt.Errorf("ack bitmap too large: %d > 32", len(a.AckBitmap))
	}

	// ACK packet: same header format but different payload
	p := &Packet{
		Version:   a.Version,
		Flags:     a.Flags | FlagACK,
		SessionID: a.SessionID,
		Seq:       a.AckBase,
		Payload:   a.AckBitmap,
	}

	return p.Marshal()
}

// Unmarshal deserializes an ACK packet
func (a *AckPacket) Unmarshal(data []byte) error {
	p := &Packet{}
	if err := p.Unmarshal(data); err != nil {
		return err
	}

	if p.Flags&FlagACK == 0 {
		return fmt.Errorf("not an ACK packet")
	}

	a.Version = p.Version
	a.Flags = p.Flags
	a.SessionID = p.SessionID
	a.AckBase = p.Seq
	a.AckBitmap = p.Payload

	return nil
}

// IsAcked checks if a specific sequence number is acknowledged in the bitmap
func (a *AckPacket) IsAcked(seq uint64) bool {
	if seq < a.AckBase {
		return true // Already past this sequence
	}

	offset := seq - a.AckBase
	if offset >= uint64(len(a.AckBitmap)*8) {
		return false // Beyond bitmap range
	}

	byteIdx := offset / 8
	bitIdx := offset % 8

	return (a.AckBitmap[byteIdx] & (1 << bitIdx)) != 0
}

// SetAcked marks a sequence number as acknowledged in the bitmap
func (a *AckPacket) SetAcked(seq uint64) {
	if seq < a.AckBase {
		return // Already acknowledged
	}

	offset := seq - a.AckBase
	if offset >= uint64(len(a.AckBitmap)*8) {
		// Need to extend bitmap
		newSize := int((offset / 8) + 1)
		if newSize > 32 {
			newSize = 32 // Cap at 256 bits
		}
		if newSize > len(a.AckBitmap) {
			newBitmap := make([]byte, newSize)
			copy(newBitmap, a.AckBitmap)
			a.AckBitmap = newBitmap
		}
	}

	if offset < uint64(len(a.AckBitmap)*8) {
		byteIdx := offset / 8
		bitIdx := offset % 8
		a.AckBitmap[byteIdx] |= (1 << bitIdx)
	}
}

// HandshakeRequest represents the TCP handshake request from client
type HandshakeRequest struct {
	ClientID string `json:"client_id"`
}

// HandshakeResponse represents the TCP handshake response from server
type HandshakeResponse struct {
	StartPort int    `json:"start_port"`
	Count     int    `json:"count"`
	Secret    string `json:"secret"`     // hex encoded
	SessionID string `json:"session_id"` // UUID
}
