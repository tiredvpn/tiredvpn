package strategy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2"
)

// TestHTTP2FrameTypes tests HTTP/2 frame type constants
func TestHTTP2FrameTypes(t *testing.T) {
	tests := []struct {
		frameType http2.FrameType
		name      string
		value     byte
	}{
		{http2.FrameData, "DATA", 0x0},
		{http2.FrameHeaders, "HEADERS", 0x1},
		{http2.FramePriority, "PRIORITY", 0x2},
		{http2.FrameRSTStream, "RST_STREAM", 0x3},
		{http2.FrameSettings, "SETTINGS", 0x4},
		{http2.FramePushPromise, "PUSH_PROMISE", 0x5},
		{http2.FramePing, "PING", 0x6},
		{http2.FrameGoAway, "GOAWAY", 0x7},
		{http2.FrameWindowUpdate, "WINDOW_UPDATE", 0x8},
		{http2.FrameContinuation, "CONTINUATION", 0x9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.frameType) != tt.value {
				t.Errorf("Frame type %s: got 0x%02x, want 0x%02x",
					tt.name, byte(tt.frameType), tt.value)
			}
		})
	}
}

// TestHTTP2FrameFlags tests HTTP/2 frame flags
func TestHTTP2FrameFlags(t *testing.T) {
	tests := []struct {
		flag  http2.Flags
		name  string
		value byte
	}{
		{http2.FlagDataEndStream, "END_STREAM", 0x1},
		{http2.FlagDataPadded, "PADDED", 0x8},
		{http2.FlagHeadersEndStream, "END_STREAM", 0x1},
		{http2.FlagHeadersEndHeaders, "END_HEADERS", 0x4},
		{http2.FlagHeadersPadded, "PADDED", 0x8},
		{http2.FlagHeadersPriority, "PRIORITY", 0x20},
		{http2.FlagSettingsAck, "ACK", 0x1},
		{http2.FlagPingAck, "ACK", 0x1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.flag) != tt.value {
				t.Errorf("Flag %s: got 0x%02x, want 0x%02x",
					tt.name, byte(tt.flag), tt.value)
			}
		})
	}
}

// TestHTTP2FrameHeader tests HTTP/2 frame header structure
func TestHTTP2FrameHeader(t *testing.T) {
	// Build a frame header (9 bytes)
	var buf bytes.Buffer

	// Length (24 bits) - 100 bytes payload
	length := uint32(100)
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	// Type - DATA frame
	buf.WriteByte(0x0)

	// Flags - END_STREAM
	buf.WriteByte(0x1)

	// Stream ID (31 bits) - stream 1
	streamID := uint32(1)
	binary.Write(&buf, binary.BigEndian, streamID)

	header := buf.Bytes()

	// Parse header
	parsedLength := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	if parsedLength != length {
		t.Errorf("Length: got %d, want %d", parsedLength, length)
	}

	frameType := header[3]
	if frameType != 0x0 {
		t.Errorf("Frame type: got 0x%02x, want 0x00 (DATA)", frameType)
	}

	flags := header[4]
	if flags != 0x1 {
		t.Errorf("Flags: got 0x%02x, want 0x01 (END_STREAM)", flags)
	}

	parsedStreamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF
	if parsedStreamID != streamID {
		t.Errorf("Stream ID: got %d, want %d", parsedStreamID, streamID)
	}
}

// TestHTTP2SettingsFrame tests SETTINGS frame format
func TestHTTP2SettingsFrame(t *testing.T) {
	// Build SETTINGS frame
	var buf bytes.Buffer

	// Frame header (9 bytes)
	buf.Write([]byte{0x00, 0x00, 0x0c}) // Length: 12 (2 settings * 6 bytes)
	buf.WriteByte(0x04)                 // Type: SETTINGS
	buf.WriteByte(0x00)                 // Flags: none
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Stream ID: 0

	// Setting 1: HEADER_TABLE_SIZE = 4096
	binary.Write(&buf, binary.BigEndian, uint16(0x1)) // ID
	binary.Write(&buf, binary.BigEndian, uint32(4096)) // Value

	// Setting 2: MAX_FRAME_SIZE = 16384
	binary.Write(&buf, binary.BigEndian, uint16(0x5)) // ID
	binary.Write(&buf, binary.BigEndian, uint32(16384)) // Value

	frame := buf.Bytes()

	// Verify frame structure
	if len(frame) != 9+12 {
		t.Errorf("Frame length: got %d, want 21", len(frame))
	}

	// Parse first setting
	settingID := binary.BigEndian.Uint16(frame[9:11])
	if settingID != 0x1 {
		t.Errorf("Setting ID: got 0x%04x, want 0x0001", settingID)
	}

	settingValue := binary.BigEndian.Uint32(frame[11:15])
	if settingValue != 4096 {
		t.Errorf("Setting value: got %d, want 4096", settingValue)
	}
}

// TestHTTP2WindowUpdateFrame tests WINDOW_UPDATE frame
func TestHTTP2WindowUpdateFrame(t *testing.T) {
	// Build WINDOW_UPDATE frame
	var buf bytes.Buffer

	// Frame header
	buf.Write([]byte{0x00, 0x00, 0x04}) // Length: 4
	buf.WriteByte(0x08)                 // Type: WINDOW_UPDATE
	buf.WriteByte(0x00)                 // Flags: none
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01}) // Stream ID: 1

	// Window size increment: 65535
	increment := uint32(65535)
	binary.Write(&buf, binary.BigEndian, increment)

	frame := buf.Bytes()

	// Parse
	parsedIncrement := binary.BigEndian.Uint32(frame[9:13]) & 0x7FFFFFFF
	if parsedIncrement != increment {
		t.Errorf("Window increment: got %d, want %d", parsedIncrement, increment)
	}
}

// TestHTTP2PingFrame tests PING frame format
func TestHTTP2PingFrame(t *testing.T) {
	// Build PING frame
	var buf bytes.Buffer

	// Frame header
	buf.Write([]byte{0x00, 0x00, 0x08}) // Length: 8 (opaque data)
	buf.WriteByte(0x06)                 // Type: PING
	buf.WriteByte(0x00)                 // Flags: none (not ACK)
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Stream ID: 0

	// Opaque data (8 bytes)
	opaqueData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	buf.Write(opaqueData)

	frame := buf.Bytes()

	// Verify
	if len(frame) != 9+8 {
		t.Errorf("PING frame length: got %d, want 17", len(frame))
	}

	parsedData := frame[9:17]
	if !bytes.Equal(parsedData, opaqueData) {
		t.Errorf("Opaque data mismatch")
	}

	// Test PING ACK
	buf.Reset()
	buf.Write([]byte{0x00, 0x00, 0x08})
	buf.WriteByte(0x06)
	buf.WriteByte(0x01) // Flags: ACK
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	buf.Write(opaqueData)

	ackFrame := buf.Bytes()
	flags := ackFrame[4]
	if flags != 0x01 {
		t.Errorf("PING ACK flags: got 0x%02x, want 0x01", flags)
	}
}

// TestHMACAuthentication tests HMAC-based authentication
func TestHMACAuthentication(t *testing.T) {
	secret := []byte("test-secret-key")
	message := []byte("test message")

	// Compute HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	// Verify HMAC
	mac2 := hmac.New(sha256.New, secret)
	mac2.Write(message)
	computedMAC := mac2.Sum(nil)

	if !hmac.Equal(expectedMAC, computedMAC) {
		t.Error("HMAC verification failed")
	}

	// Test with wrong secret
	wrongSecret := []byte("wrong-secret")
	mac3 := hmac.New(sha256.New, wrongSecret)
	mac3.Write(message)
	wrongMAC := mac3.Sum(nil)

	if hmac.Equal(expectedMAC, wrongMAC) {
		t.Error("HMAC should not match with wrong secret")
	}
}

// TestHTTP2DataFramePadding tests DATA frame with padding
func TestHTTP2DataFramePadding(t *testing.T) {
	// Build DATA frame with padding
	var buf bytes.Buffer

	payload := []byte("test data")
	paddingLen := byte(10)

	// Frame header
	totalLen := 1 + len(payload) + int(paddingLen) // padding length byte + payload + padding
	buf.WriteByte(byte(totalLen >> 16))
	buf.WriteByte(byte(totalLen >> 8))
	buf.WriteByte(byte(totalLen))
	buf.WriteByte(0x0)  // Type: DATA
	buf.WriteByte(0x8)  // Flags: PADDED
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01}) // Stream ID: 1

	// Payload
	buf.WriteByte(paddingLen) // Padding length
	buf.Write(payload)        // Data
	buf.Write(make([]byte, paddingLen)) // Padding

	frame := buf.Bytes()

	// Parse
	frameLen := uint32(frame[0])<<16 | uint32(frame[1])<<8 | uint32(frame[2])
	if frameLen != uint32(totalLen) {
		t.Errorf("Frame length: got %d, want %d", frameLen, totalLen)
	}

	flags := frame[4]
	if flags&0x8 == 0 {
		t.Error("PADDED flag should be set")
	}

	parsedPaddingLen := frame[9]
	if parsedPaddingLen != paddingLen {
		t.Errorf("Padding length: got %d, want %d", parsedPaddingLen, paddingLen)
	}

	// Extract payload
	payloadStart := 10
	payloadEnd := payloadStart + len(payload)
	parsedPayload := frame[payloadStart:payloadEnd]

	if !bytes.Equal(parsedPayload, payload) {
		t.Error("Payload mismatch")
	}
}

// TestHTTP2StreamPriority tests stream priority fields
func TestHTTP2StreamPriority(t *testing.T) {
	// Priority fields (5 bytes):
	// - Bit 0-30: Stream dependency
	// - Bit 31: Exclusive flag
	// - Byte 4: Weight (1-256, encoded as 0-255)

	dependsOn := uint32(3)
	exclusive := true
	weight := byte(100)

	// Build priority field
	var buf bytes.Buffer
	priorityField := dependsOn
	if exclusive {
		priorityField |= 0x80000000
	}
	binary.Write(&buf, binary.BigEndian, priorityField)
	buf.WriteByte(weight)

	priority := buf.Bytes()

	// Parse
	parsedField := binary.BigEndian.Uint32(priority[0:4])
	parsedExclusive := (parsedField & 0x80000000) != 0
	parsedDependsOn := parsedField & 0x7FFFFFFF
	parsedWeight := priority[4]

	if parsedDependsOn != dependsOn {
		t.Errorf("Depends on: got %d, want %d", parsedDependsOn, dependsOn)
	}
	if parsedExclusive != exclusive {
		t.Errorf("Exclusive: got %v, want %v", parsedExclusive, exclusive)
	}
	if parsedWeight != weight {
		t.Errorf("Weight: got %d, want %d", parsedWeight, weight)
	}
}

// TestHTTP2MaxFrameSize tests maximum frame size limits
func TestHTTP2MaxFrameSize(t *testing.T) {
	tests := []struct {
		size  uint32
		valid bool
		name  string
	}{
		{16384, true, "Default max (16KB)"},
		{32768, true, "32KB"},
		{65536, true, "64KB"},
		{16777215, true, "Maximum (16MB)"},
		{16777216, false, "Over maximum"},
		{16383, false, "Below minimum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Valid range: 16384 to 16777215
			valid := tt.size >= 16384 && tt.size <= 16777215
			if valid != tt.valid {
				t.Errorf("Size %d validity: got %v, want %v", tt.size, valid, tt.valid)
			}
		})
	}
}

// TestHTTP2Preface tests HTTP/2 connection preface
func TestHTTP2Preface(t *testing.T) {
	// HTTP/2 connection preface (magic string)
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	expectedBytes := []byte(preface)

	if len(expectedBytes) != 24 {
		t.Errorf("Preface length: got %d, want 24", len(expectedBytes))
	}

	// Verify magic bytes
	if string(expectedBytes[:3]) != "PRI" {
		t.Error("Preface should start with PRI")
	}

	if string(expectedBytes[len(expectedBytes)-6:]) != "SM\r\n\r\n" {
		t.Error("Preface should end with SM\\r\\n\\r\\n")
	}
}
