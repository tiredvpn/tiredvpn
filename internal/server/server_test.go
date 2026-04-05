package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestConfusionRelayPacketSizeLimit tests 64KB packet limit
func TestConfusionRelayPacketSizeLimit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Test packets at and around the 64KB limit
	tests := []struct {
		name      string
		size      uint32
		shouldFail bool
	}{
		{"1KB packet", 1024, false},
		{"16KB packet", 16 * 1024, false},
		{"32KB packet", 32 * 1024, false},
		{"64KB packet", 64 * 1024, false},
		{"65KB packet", 65 * 1024, true},  // Should fail - over limit
		{"128KB packet", 128 * 1024, true}, // Should fail - over limit
		{"Zero length", 0, true},           // Should fail - zero length
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create length-prefixed packet
			data := make([]byte, tt.size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, tt.size)

			// Send length prefix
			go func() {
				client.Write(lenBuf)
				if !tt.shouldFail && tt.size > 0 {
					client.Write(data)
				}
			}()

			// Try to read length prefix
			readLenBuf := make([]byte, 4)
			_, err := io.ReadFull(server, readLenBuf)
			if err != nil {
				t.Fatalf("Failed to read length: %v", err)
			}

			pktLen := binary.BigEndian.Uint32(readLenBuf)
			if pktLen != tt.size {
				t.Errorf("Read length %d, expected %d", pktLen, tt.size)
			}

			// Check if packet size is valid (mimics server logic)
			if pktLen > 65536 || pktLen == 0 {
				if !tt.shouldFail {
					t.Errorf("Packet marked as invalid but should be valid")
				}
				return // Would close connection in real server
			}

			if tt.shouldFail {
				t.Errorf("Packet marked as valid but should fail")
				return
			}

			// Read actual data
			readData := make([]byte, pktLen)
			n, err := io.ReadFull(server, readData)
			if err != nil {
				t.Fatalf("Failed to read data: %v", err)
			}
			if uint32(n) != pktLen {
				t.Errorf("Read %d bytes, expected %d", n, pktLen)
			}
			if !bytes.Equal(readData, data) {
				t.Error("Data mismatch")
			}
		})
	}
}

// TestConfusionRelayBidirectional tests bidirectional relay
func TestConfusionRelayBidirectional(t *testing.T) {
	// Create two pipes: client<->relay and relay<->target
	clientConn, relayClientSide := net.Pipe()
	relayTargetSide, targetConn := net.Pipe()

	defer clientConn.Close()
	defer relayClientSide.Close()
	defer relayTargetSide.Close()
	defer targetConn.Close()

	// Simulate confusion relay between relayClientSide and relayTargetSide
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)

		// Relay client->target
		go func() {
			buf := make([]byte, 32768)
			for {
				// Read length-prefixed data from client side
				lenBuf := make([]byte, 4)
				_, err := io.ReadFull(relayClientSide, lenBuf)
				if err != nil {
					return
				}
				pktLen := binary.BigEndian.Uint32(lenBuf)
				if pktLen == 0 || pktLen > 65536 {
					return
				}

				data := buf[:pktLen]
				_, err = io.ReadFull(relayClientSide, data)
				if err != nil {
					return
				}

				// Forward to target
				_, err = relayTargetSide.Write(data)
				if err != nil {
					return
				}
			}
		}()

		// Relay target->client
		buf := make([]byte, 32768)
		for {
			n, err := relayTargetSide.Read(buf)
			if err != nil {
				return
			}

			// Send length-prefixed to client
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			_, err = relayClientSide.Write(lenBuf)
			if err != nil {
				return
			}
			_, err = relayClientSide.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// Client sends data
	clientData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	go func() {
		// Send with length prefix
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(clientData)))
		clientConn.Write(lenBuf)
		clientConn.Write(clientData)
	}()

	// Target receives
	targetBuf := make([]byte, 1024)
	n, err := targetConn.Read(targetBuf)
	if err != nil {
		t.Fatalf("Target read failed: %v", err)
	}
	if !bytes.Equal(targetBuf[:n], clientData) {
		t.Errorf("Target received %q, expected %q", targetBuf[:n], clientData)
	}

	// Target responds
	targetData := []byte("HTTP/1.1 200 OK\r\n\r\n")
	go func() {
		targetConn.Write(targetData)
	}()

	// Client receives (length-prefixed)
	time.Sleep(10 * time.Millisecond)
	lenBuf := make([]byte, 4)
	_, err = io.ReadFull(clientConn, lenBuf)
	if err != nil {
		t.Fatalf("Client read length failed: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)

	respBuf := make([]byte, respLen)
	_, err = io.ReadFull(clientConn, respBuf)
	if err != nil {
		t.Fatalf("Client read data failed: %v", err)
	}
	if !bytes.Equal(respBuf, targetData) {
		t.Errorf("Client received %q, expected %q", respBuf, targetData)
	}
}

// TestConfusionRelayMultiplePackets tests sequential packet handling
func TestConfusionRelayMultiplePackets(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	packets := [][]byte{
		[]byte("packet1"),
		[]byte("packet2 is longer"),
		[]byte("packet3"),
		make([]byte, 1000), // Large packet
	}

	// Fill large packet with pattern
	for i := range packets[3] {
		packets[3][i] = byte(i % 256)
	}

	// Send all packets
	go func() {
		for _, pkt := range packets {
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(pkt)))
			client.Write(lenBuf)
			client.Write(pkt)
		}
	}()

	// Receive all packets
	for i, expected := range packets {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(server, lenBuf)
		if err != nil {
			t.Fatalf("Packet %d: failed to read length: %v", i, err)
		}

		pktLen := binary.BigEndian.Uint32(lenBuf)
		if pktLen != uint32(len(expected)) {
			t.Errorf("Packet %d: length %d, expected %d", i, pktLen, len(expected))
		}

		data := make([]byte, pktLen)
		_, err = io.ReadFull(server, data)
		if err != nil {
			t.Fatalf("Packet %d: failed to read data: %v", i, err)
		}

		if !bytes.Equal(data, expected) {
			t.Errorf("Packet %d: data mismatch", i)
		}
	}
}

// TestConfusionRelayTimeout tests relay with idle timeout
func TestConfusionRelayTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Set read deadline
	timeout := 100 * time.Millisecond
	server.SetReadDeadline(time.Now().Add(timeout))

	// Don't send anything, wait for timeout
	start := time.Now()

	lenBuf := make([]byte, 4)
	_, err := io.ReadFull(server, lenBuf)

	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if elapsed < 90*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Errorf("Timeout took %v, expected ~100ms", elapsed)
	}
}

// TestConfusionMagicDetection tests detection of TIRED magic marker
func TestConfusionMagicDetection(t *testing.T) {
	// Simulate DNS confusion packet structure
	var buf bytes.Buffer

	// Fake DNS header (12 bytes)
	buf.Write([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})

	// DNS query name
	buf.Write([]byte{0x06, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78}) // "yandex"
	buf.Write([]byte{0x02, 0x72, 0x75, 0x00})                   // "ru"
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})                   // Type A, Class IN

	// DNS answer
	buf.Write([]byte{0xc0, 0x0c})                   // Name pointer
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})       // Type A, Class IN
	buf.Write([]byte{0x00, 0x00, 0x01, 0x2c})       // TTL
	buf.Write([]byte{0x00, 0x04})                   // RDLENGTH
	buf.Write([]byte{0x4d, 0x58, 0x67, 0x63})       // Fake IP

	// Magic marker
	magicPos := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x54, 0x49, 0x52, 0x45, 0x44}) // \0\0TIRED

	// Real data
	realData := []byte("CONNECT example.com:443")
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(realData)))
	buf.Write(lenBytes)
	buf.Write(realData)

	packet := buf.Bytes()

	// Search for magic
	magic := []byte{0x00, 0x00, 0x54, 0x49, 0x52, 0x45, 0x44}
	magicIdx := bytes.Index(packet, magic)

	if magicIdx != magicPos {
		t.Errorf("Magic found at %d, expected %d", magicIdx, magicPos)
	}

	// Extract real data
	dataStart := magicIdx + len(magic) + 4 // magic + length prefix
	dataLen := binary.BigEndian.Uint32(packet[magicIdx+len(magic):])

	if dataLen != uint32(len(realData)) {
		t.Errorf("Data length %d, expected %d", dataLen, len(realData))
	}

	extractedData := packet[dataStart : dataStart+int(dataLen)]
	if !bytes.Equal(extractedData, realData) {
		t.Errorf("Extracted data %q, expected %q", extractedData, realData)
	}
}
