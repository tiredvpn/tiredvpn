package geneva

import (
	"encoding/binary"
	"errors"
)

// Primitive represents a Geneva packet manipulation primitive
type Primitive interface {
	// Apply executes the primitive on a TCP packet
	Apply(packet []byte) ([][]byte, error)
	// String returns a human-readable description
	String() string
}

// Action represents a Geneva action with optional parameters
type Action struct {
	Type   ActionType
	Params map[string]interface{}
}

// ActionType defines the type of Geneva primitive
type ActionType int

const (
	ActionDrop ActionType = iota
	ActionTamper
	ActionFragment
	ActionDuplicate
	ActionSend
)

// String returns the action type name
func (a ActionType) String() string {
	switch a {
	case ActionDrop:
		return "drop"
	case ActionTamper:
		return "tamper"
	case ActionFragment:
		return "fragment"
	case ActionDuplicate:
		return "duplicate"
	case ActionSend:
		return "send"
	default:
		return "unknown"
	}
}

// DropPrimitive drops a packet (returns empty list)
type DropPrimitive struct{}

// NewDropPrimitive creates a drop primitive
func NewDropPrimitive() *DropPrimitive {
	return &DropPrimitive{}
}

// Apply drops the packet
func (d *DropPrimitive) Apply(packet []byte) ([][]byte, error) {
	return nil, nil // Empty list = packet dropped
}

// String returns description
func (d *DropPrimitive) String() string {
	return "drop"
}

// TamperPrimitive modifies TCP header fields
type TamperPrimitive struct {
	Field string      // "flags", "seq", "ack", "win", "chksum"
	Value interface{} // New value or modification
}

// NewTamperPrimitive creates a tamper primitive
func NewTamperPrimitive(field string, value interface{}) *TamperPrimitive {
	return &TamperPrimitive{
		Field: field,
		Value: value,
	}
}

// Apply modifies TCP header field
func (t *TamperPrimitive) Apply(packet []byte) ([][]byte, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}

	// Parse IP header
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}

	// Create modified copy
	modified := make([]byte, len(packet))
	copy(modified, packet)

	tcpStart := ipHeaderLen

	switch t.Field {
	case "flags":
		// TCP flags are at offset 13 in TCP header
		if val, ok := t.Value.(uint8); ok {
			modified[tcpStart+13] = val
		}
	case "seq":
		// TCP sequence number at offset 4
		if val, ok := t.Value.(uint32); ok {
			binary.BigEndian.PutUint32(modified[tcpStart+4:], val)
		}
	case "ack":
		// TCP acknowledgment number at offset 8
		if val, ok := t.Value.(uint32); ok {
			binary.BigEndian.PutUint32(modified[tcpStart+8:], val)
		}
	case "win":
		// TCP window size at offset 14
		if val, ok := t.Value.(uint16); ok {
			binary.BigEndian.PutUint16(modified[tcpStart+14:], val)
		}
	case "chksum":
		// TCP checksum at offset 16
		if val, ok := t.Value.(uint16); ok {
			binary.BigEndian.PutUint16(modified[tcpStart+16:], val)
		}
	case "ttl":
		// IP TTL at offset 8
		if val, ok := t.Value.(uint8); ok {
			modified[8] = val
			// Recalculate IP checksum
			recalculateIPChecksum(modified)
		}
	default:
		return nil, errors.New("unknown tamper field: " + t.Field)
	}

	return [][]byte{modified}, nil
}

// String returns description
func (t *TamperPrimitive) String() string {
	return "tamper{" + t.Field + "}"
}

// FragmentPrimitive splits TCP payload into smaller segments
type FragmentPrimitive struct {
	Offset int // Byte offset to fragment at
	Size   int // Fragment size (if Offset is 0, use Size for equal chunks)
}

// NewFragmentPrimitive creates a fragment primitive
func NewFragmentPrimitive(offset, size int) *FragmentPrimitive {
	return &FragmentPrimitive{
		Offset: offset,
		Size:   size,
	}
}

// Apply fragments the packet
func (f *FragmentPrimitive) Apply(packet []byte) ([][]byte, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}

	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}

	tcpStart := ipHeaderLen
	tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
	payloadStart := tcpStart + tcpHeaderLen

	if len(packet) <= payloadStart {
		// No payload to fragment
		return [][]byte{packet}, nil
	}

	payload := packet[payloadStart:]

	// Determine fragment offset
	fragmentOffset := f.Offset
	if fragmentOffset == 0 && f.Size > 0 {
		fragmentOffset = f.Size
	}

	if fragmentOffset <= 0 || fragmentOffset >= len(payload) {
		// Invalid offset, return original
		return [][]byte{packet}, nil
	}

	// Create two fragments
	header := packet[:payloadStart]

	// First fragment: header + payload[:offset]
	frag1 := make([]byte, len(header)+fragmentOffset)
	copy(frag1, header)
	copy(frag1[payloadStart:], payload[:fragmentOffset])

	// Update IP total length
	binary.BigEndian.PutUint16(frag1[2:4], uint16(len(frag1)))
	recalculateIPChecksum(frag1)

	// Second fragment: header + payload[offset:]
	frag2 := make([]byte, len(header)+len(payload)-fragmentOffset)
	copy(frag2, header)
	copy(frag2[payloadStart:], payload[fragmentOffset:])

	// Update sequence number for second fragment
	seqNum := binary.BigEndian.Uint32(frag2[tcpStart+4:])
	seqNum += uint32(fragmentOffset)
	binary.BigEndian.PutUint32(frag2[tcpStart+4:], seqNum)

	// Update IP total length
	binary.BigEndian.PutUint16(frag2[2:4], uint16(len(frag2)))
	recalculateIPChecksum(frag2)

	return [][]byte{frag1, frag2}, nil
}

// String returns description
func (f *FragmentPrimitive) String() string {
	if f.Offset > 0 {
		return "fragment{offset=" + string(rune(f.Offset)) + "}"
	}
	return "fragment{size=" + string(rune(f.Size)) + "}"
}

// DuplicatePrimitive sends a duplicate packet
type DuplicatePrimitive struct {
	Count int // Number of duplicates (default 1)
}

// NewDuplicatePrimitive creates a duplicate primitive
func NewDuplicatePrimitive(count int) *DuplicatePrimitive {
	if count < 1 {
		count = 1
	}
	return &DuplicatePrimitive{
		Count: count,
	}
}

// Apply duplicates the packet
func (d *DuplicatePrimitive) Apply(packet []byte) ([][]byte, error) {
	result := make([][]byte, d.Count+1)

	// Original packet
	result[0] = packet

	// Duplicates
	for i := 0; i < d.Count; i++ {
		dup := make([]byte, len(packet))
		copy(dup, packet)
		result[i+1] = dup
	}

	return result, nil
}

// String returns description
func (d *DuplicatePrimitive) String() string {
	if d.Count == 1 {
		return "duplicate"
	}
	return "duplicate{count=" + string(rune(d.Count)) + "}"
}

// SendPrimitive sends a packet as-is (no-op)
type SendPrimitive struct{}

// NewSendPrimitive creates a send primitive
func NewSendPrimitive() *SendPrimitive {
	return &SendPrimitive{}
}

// Apply returns the packet unmodified
func (s *SendPrimitive) Apply(packet []byte) ([][]byte, error) {
	return [][]byte{packet}, nil
}

// String returns description
func (s *SendPrimitive) String() string {
	return "send"
}

// recalculateIPChecksum recalculates IP header checksum
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Zero out existing checksum
	packet[10] = 0
	packet[11] = 0

	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if ipHeaderLen > len(packet) {
		return
	}

	// Calculate checksum
	var sum uint32
	for i := 0; i < ipHeaderLen; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// Add carry
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	checksum := uint16(^sum)

	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)
}

// TCPFlags represents TCP header flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
	TCPFlagECE = 0x40
	TCPFlagCWR = 0x80
)

// ParseTCPFlags parses TCP flags from packet
func ParseTCPFlags(packet []byte) (uint8, error) {
	if len(packet) < 20 {
		return 0, errors.New("packet too short for IP header")
	}

	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return 0, errors.New("packet too short for TCP header")
	}

	return packet[ipHeaderLen+13], nil
}
