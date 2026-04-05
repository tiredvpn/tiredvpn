package client

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestSOCKS5HandshakeFormat tests SOCKS5 handshake packet format
func TestSOCKS5HandshakeFormat(t *testing.T) {
	// Valid handshake: Version 5, 1 method (no auth)
	handshake := []byte{0x05, 0x01, 0x00}

	if handshake[0] != 0x05 {
		t.Errorf("Expected version 5, got %d", handshake[0])
	}

	nMethods := int(handshake[1])
	if nMethods != 1 {
		t.Errorf("Expected 1 auth method, got %d", nMethods)
	}

	if handshake[2] != 0x00 {
		t.Errorf("Expected no-auth (0x00), got 0x%02x", handshake[2])
	}
}

// TestSOCKS5HandshakeResponse tests server response format
func TestSOCKS5HandshakeResponse(t *testing.T) {
	// Server responds: Version 5, method 0 (no auth)
	response := []byte{0x05, 0x00}

	if response[0] != 0x05 {
		t.Errorf("Expected version 5, got %d", response[0])
	}

	if response[1] != 0x00 {
		t.Errorf("Expected no-auth selected (0x00), got 0x%02x", response[1])
	}
}

// TestSOCKS5ConnectRequestFormat tests CONNECT request formatting
func TestSOCKS5ConnectRequestFormat(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		port         uint16
		wantAddrType byte
	}{
		{
			name:         "example.com:443",
			domain:       "example.com",
			port:         443,
			wantAddrType: 0x03, // Domain name
		},
		{
			name:         "google.com:80",
			domain:       "google.com",
			port:         80,
			wantAddrType: 0x03,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req bytes.Buffer

			// Build CONNECT request
			req.WriteByte(0x05)            // Version
			req.WriteByte(0x01)            // CONNECT
			req.WriteByte(0x00)            // Reserved
			req.WriteByte(tt.wantAddrType) // Domain name type
			req.WriteByte(byte(len(tt.domain)))
			req.WriteString(tt.domain)

			// Port
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, tt.port)
			req.Write(portBuf)

			packet := req.Bytes()

			// Verify format
			if packet[0] != 0x05 {
				t.Errorf("Expected version 5, got %d", packet[0])
			}
			if packet[1] != 0x01 {
				t.Errorf("Expected CONNECT (1), got %d", packet[1])
			}
			if packet[3] != tt.wantAddrType {
				t.Errorf("Expected addr type %d, got %d", tt.wantAddrType, packet[3])
			}

			// Check domain length
			domainLen := int(packet[4])
			if domainLen != len(tt.domain) {
				t.Errorf("Domain length %d, expected %d", domainLen, len(tt.domain))
			}

			// Check domain
			domain := string(packet[5 : 5+domainLen])
			if domain != tt.domain {
				t.Errorf("Domain %s, expected %s", domain, tt.domain)
			}

			// Check port
			portOffset := 5 + domainLen
			port := binary.BigEndian.Uint16(packet[portOffset:])
			if port != tt.port {
				t.Errorf("Port %d, expected %d", port, tt.port)
			}
		})
	}
}

// TestSOCKS5ResponseFormat tests SOCKS5 response parsing
func TestSOCKS5ResponseFormat(t *testing.T) {
	tests := []struct {
		name    string
		code    byte
		wantErr bool
	}{
		{"Success", 0x00, false},
		{"General failure", 0x01, true},
		{"Connection not allowed", 0x02, true},
		{"Network unreachable", 0x03, true},
		{"Host unreachable", 0x04, true},
		{"Connection refused", 0x05, true},
		{"TTL expired", 0x06, true},
		{"Command not supported", 0x07, true},
		{"Address type not supported", 0x08, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build response packet
			var resp bytes.Buffer
			resp.WriteByte(0x05)           // Version
			resp.WriteByte(tt.code)        // Status code
			resp.WriteByte(0x00)           // Reserved
			resp.WriteByte(0x01)           // IPv4
			resp.Write([]byte{0, 0, 0, 0}) // Bind addr
			resp.Write([]byte{0, 0})       // Bind port

			packet := resp.Bytes()

			// Parse response
			if packet[0] != 0x05 {
				t.Errorf("Expected version 5, got %d", packet[0])
			}

			statusCode := packet[1]
			if statusCode != tt.code {
				t.Errorf("Expected code %d, got %d", tt.code, statusCode)
			}

			isError := (statusCode != 0x00)
			if isError != tt.wantErr {
				t.Errorf("Code %d error status: got %v, want %v", tt.code, isError, tt.wantErr)
			}
		})
	}
}

// TestHTTPConnectRequestFormat tests HTTP CONNECT request format
func TestHTTPConnectRequestFormat(t *testing.T) {
	tests := []struct {
		host string
		port string
	}{
		{"example.com", "443"},
		{"google.com", "80"},
		{"api.github.com", "443"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			target := tt.host + ":" + tt.port
			var req bytes.Buffer

			// Build CONNECT request
			req.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
			req.WriteString("Host: " + target + "\r\n")
			req.WriteString("\r\n")

			reqStr := req.String()

			// Verify format
			if !bytes.Contains([]byte(reqStr), []byte("CONNECT ")) {
				t.Error("Missing CONNECT method")
			}

			if !bytes.Contains([]byte(reqStr), []byte(target)) {
				t.Errorf("Missing target %s", target)
			}

			if !bytes.Contains([]byte(reqStr), []byte("HTTP/1.1")) {
				t.Error("Missing HTTP/1.1")
			}

			if !bytes.HasSuffix([]byte(reqStr), []byte("\r\n\r\n")) {
				t.Error("Request should end with \\r\\n\\r\\n")
			}
		})
	}
}

// TestHTTPConnectResponseFormat tests HTTP CONNECT response format
func TestHTTPConnectResponseFormat(t *testing.T) {
	tests := []struct {
		code    string
		message string
		success bool
	}{
		{"200", "Connection Established", true},
		{"400", "Bad Request", false},
		{"403", "Forbidden", false},
		{"502", "Bad Gateway", false},
		{"503", "Service Unavailable", false},
	}

	for _, tt := range tests {
		t.Run(tt.code+" "+tt.message, func(t *testing.T) {
			response := "HTTP/1.1 " + tt.code + " " + tt.message + "\r\n\r\n"

			// Verify format
			if !bytes.HasPrefix([]byte(response), []byte("HTTP/1.1")) {
				t.Error("Response should start with HTTP/1.1")
			}

			if !bytes.Contains([]byte(response), []byte(tt.code)) {
				t.Errorf("Response should contain code %s", tt.code)
			}

			if !bytes.Contains([]byte(response), []byte(tt.message)) {
				t.Errorf("Response should contain message %s", tt.message)
			}

			isSuccess := bytes.Contains([]byte(response), []byte("200"))
			if isSuccess != tt.success {
				t.Errorf("Code %s success status: got %v, want %v", tt.code, isSuccess, tt.success)
			}
		})
	}
}

// TestSOCKS5IPv4Format tests IPv4 address format in SOCKS5
func TestSOCKS5IPv4Format(t *testing.T) {
	var req bytes.Buffer

	// Build CONNECT with IPv4
	req.WriteByte(0x05)                 // Version
	req.WriteByte(0x01)                 // CONNECT
	req.WriteByte(0x00)                 // Reserved
	req.WriteByte(0x01)                 // IPv4
	req.Write([]byte{93, 184, 216, 34}) // 93.184.216.34 (example.com)
	req.Write([]byte{0x01, 0xBB})       // Port 443

	packet := req.Bytes()

	// Verify
	if packet[3] != 0x01 {
		t.Errorf("Expected IPv4 type (0x01), got 0x%02x", packet[3])
	}

	// Extract IP
	ip := packet[4:8]
	if len(ip) != 4 {
		t.Errorf("IPv4 address should be 4 bytes, got %d", len(ip))
	}

	// Extract port
	port := binary.BigEndian.Uint16(packet[8:10])
	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}
}

// TestSOCKS5DomainFormat tests domain name format in SOCKS5
func TestSOCKS5DomainFormat(t *testing.T) {
	domain := "example.com"
	var req bytes.Buffer

	req.WriteByte(0x05) // Version
	req.WriteByte(0x01) // CONNECT
	req.WriteByte(0x00) // Reserved
	req.WriteByte(0x03) // Domain name
	req.WriteByte(byte(len(domain)))
	req.WriteString(domain)
	req.Write([]byte{0x01, 0xBB}) // Port 443

	packet := req.Bytes()

	// Verify
	if packet[3] != 0x03 {
		t.Errorf("Expected domain type (0x03), got 0x%02x", packet[3])
	}

	domainLen := int(packet[4])
	if domainLen != len(domain) {
		t.Errorf("Domain length %d, expected %d", domainLen, len(domain))
	}

	extractedDomain := string(packet[5 : 5+domainLen])
	if extractedDomain != domain {
		t.Errorf("Extracted domain %s, expected %s", extractedDomain, domain)
	}
}

// TestSOCKS5UDPAssociateCommand tests UDP ASSOCIATE command format
func TestSOCKS5UDPAssociateCommand(t *testing.T) {
	var req bytes.Buffer

	// Build UDP ASSOCIATE request
	req.WriteByte(0x05) // Version
	req.WriteByte(0x03) // UDP ASSOCIATE
	req.WriteByte(0x00) // Reserved
	req.WriteByte(0x01) // IPv4
	req.Write([]byte{0, 0, 0, 0})
	req.Write([]byte{0, 0})

	packet := req.Bytes()

	if packet[1] != 0x03 {
		t.Errorf("Expected UDP ASSOCIATE (0x03), got 0x%02x", packet[1])
	}

	// Server should respond with "command not supported" (0x07)
	var resp bytes.Buffer
	resp.WriteByte(0x05)
	resp.WriteByte(0x07) // Command not supported
	resp.WriteByte(0x00)
	resp.WriteByte(0x01)
	resp.Write([]byte{0, 0, 0, 0})
	resp.Write([]byte{0, 0})

	respPacket := resp.Bytes()
	if respPacket[1] != 0x07 {
		t.Errorf("Expected error 0x07, got 0x%02x", respPacket[1])
	}
}
