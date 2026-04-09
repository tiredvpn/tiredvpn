package strategy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/padding"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TiredVPN Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// mockWebSocketPaddedServer simulates server-side WebSocket Padded handler
func mockWebSocketPaddedServer(listener net.Listener, secret []byte, tlsCert tls.Certificate, wg *sync.WaitGroup) {
	defer wg.Done()

	// Wrap listener with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer c.Close()

			// Read WebSocket upgrade request
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				return
			}

			request := string(buf[:n])

			// Check for X-Salamander-Version header
			if !contains(request, "X-Salamander-Version: 1.0") {
				return
			}

			// Send WebSocket upgrade response
			response := "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
				"\r\n"

			if _, err := c.Write([]byte(response)); err != nil {
				return
			}

			// Wrap with Salamander
			padder := padding.NewSalamanderPadder(secret, padding.Balanced)
			salamanderConn := NewSalamanderConn(c, padder, false)

			// Echo back data
			echoBuffer := make([]byte, 4096)
			for {
				n, err := salamanderConn.Read(echoBuffer)
				if err != nil {
					return
				}

				if _, err := salamanderConn.Write(echoBuffer[:n]); err != nil {
					return
				}
			}
		}(conn)
	}
}

// TestWebSocketPaddedIntegration tests full WebSocket Padded client-server flow
func TestWebSocketPaddedIntegration(t *testing.T) {
	secret := []byte("test-websocket-secret-key-12345")

	// Generate TLS certificate
	tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockWebSocketPaddedServer(listener, secret, tlsCert, &wg)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client strategy with manager pointing to our test server
	mgr := NewManager()
	mgr.serverAddrV4 = addr
	strategy := NewWebSocketPaddedStrategy(mgr, secret)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := strategy.Connect(ctx, "example.com:80")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Test data transmission
	testData := []byte("Hello WebSocket Padded!")

	// Write test data
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Read echo response
	response := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	// Verify echo
	if string(response) != string(testData) {
		t.Errorf("Echo mismatch: got %q, want %q", response, testData)
	}

	listener.Close()
	wg.Wait()
}

// mockQUICSalamanderServer simulates QUIC Salamander server
func mockQUICSalamanderServer(conn net.PacketConn, secret []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	padder := padding.NewSalamanderPadder(secret, padding.Balanced)
	salamanderConn := padding.NewSalamanderPacketConn(conn, padder)

	buf := make([]byte, 65536)
	for {
		n, addr, err := salamanderConn.ReadFrom(buf)
		if err != nil {
			return
		}

		// Echo back
		if _, err := salamanderConn.WriteTo(buf[:n], addr); err != nil {
			return
		}
	}
}

// TestQUICSalamanderUDPIntegration tests Salamander UDP wrapper
func TestQUICSalamanderUDPIntegration(t *testing.T) {
	secret := []byte("test-quic-salamander-secret-32b")

	// Start mock UDP server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start UDP listener: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockQUICSalamanderServer(serverConn, secret, &wg)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client connection
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client UDP: %v", err)
	}
	defer clientConn.Close()

	// Wrap with Salamander
	padder := padding.NewSalamanderPadder(secret, padding.Balanced)
	salamanderClient := padding.NewSalamanderPacketConn(clientConn, padder)

	// Test data transmission
	testData := []byte("QUIC Salamander Test Packet")

	// Resolve server address
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to resolve server addr: %v", err)
	}

	// Write test packet
	if _, err := salamanderClient.WriteTo(testData, udpAddr); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	// Read echo response
	response := make([]byte, 65536)
	salamanderClient.SetReadDeadline(time.Now().Add(2 * time.Second))

	n, _, err := salamanderClient.ReadFrom(response)
	if err != nil {
		t.Fatalf("Failed to read packet: %v", err)
	}

	// Verify echo
	if string(response[:n]) != string(testData) {
		t.Errorf("Echo mismatch: got %q, want %q", response[:n], testData)
	}

	serverConn.Close()
	wg.Wait()
}

// TestWebSocketPaddedMultipleMessages tests multiple message exchange
func TestWebSocketPaddedMultipleMessages(t *testing.T) {
	secret := []byte("test-multi-message-secret-key-x")

	tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockWebSocketPaddedServer(listener, secret, tlsCert, &wg)

	time.Sleep(100 * time.Millisecond)

	mgr := NewManager()
	mgr.serverAddrV4 = addr
	strategy := NewWebSocketPaddedStrategy(mgr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := strategy.Connect(ctx, "example.com:80")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send multiple messages
	messages := []string{
		"First message",
		"Second message with more data",
		"Third message",
		"Fourth message - longer text to test bucket normalization in Salamander padding",
	}

	for i, msg := range messages {
		// Write
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("Failed to write message %d: %v", i, err)
		}

		// Read echo
		response := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("Failed to read message %d: %v", i, err)
		}

		// Verify
		if string(response) != msg {
			t.Errorf("Message %d mismatch: got %q, want %q", i, response, msg)
		}
	}

	listener.Close()
	wg.Wait()
}

// TestQUICSalamanderPaddingLevels tests different padding levels
func TestQUICSalamanderPaddingLevels(t *testing.T) {
	secret := []byte("test-padding-levels-secret-key!")

	levels := []padding.PaddingLevel{
		padding.Conservative,
		padding.Balanced,
		padding.Aggressive,
	}

	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			// Start server with specific padding level
			serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start UDP listener: %v", err)
			}
			defer serverConn.Close()

			serverAddr := serverConn.LocalAddr().String()

			padder := padding.NewSalamanderPadder(secret, level)
			salamanderServer := padding.NewSalamanderPacketConn(serverConn, padder)

			var wg sync.WaitGroup
			wg.Add(1)

			go func() {
				defer wg.Done()
				buf := make([]byte, 65536)
				for {
					n, addr, err := salamanderServer.ReadFrom(buf)
					if err != nil {
						return
					}
					salamanderServer.WriteTo(buf[:n], addr)
				}
			}()

			time.Sleep(50 * time.Millisecond)

			// Create client with same padding level
			clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to create client UDP: %v", err)
			}
			defer clientConn.Close()

			clientPadder := padding.NewSalamanderPadder(secret, level)
			salamanderClient := padding.NewSalamanderPacketConn(clientConn, clientPadder)

			// Test data
			testData := []byte("Padding level test: " + level.String())

			udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				t.Fatalf("Failed to resolve addr: %v", err)
			}

			// Send and receive
			if _, err := salamanderClient.WriteTo(testData, udpAddr); err != nil {
				t.Fatalf("Failed to write: %v", err)
			}

			response := make([]byte, 65536)
			salamanderClient.SetReadDeadline(time.Now().Add(2 * time.Second))

			n, _, err := salamanderClient.ReadFrom(response)
			if err != nil {
				t.Fatalf("Failed to read: %v", err)
			}

			if string(response[:n]) != string(testData) {
				t.Errorf("Mismatch for level %s: got %q, want %q", level, response[:n], testData)
			}

			serverConn.Close()
			wg.Wait()
		})
	}
}

// TestWebSocketPaddedLargePayload tests large data transfer
func TestWebSocketPaddedLargePayload(t *testing.T) {
	secret := []byte("test-large-payload-secret-key!!")

	tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockWebSocketPaddedServer(listener, secret, tlsCert, &wg)

	time.Sleep(100 * time.Millisecond)

	mgr := NewManager()
	mgr.serverAddrV4 = addr
	strategy := NewWebSocketPaddedStrategy(mgr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := strategy.Connect(ctx, "example.com:80")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create 50KB payload
	largeData := make([]byte, 50*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Write large payload
	if _, err := conn.Write(largeData); err != nil {
		t.Fatalf("Failed to write large payload: %v", err)
	}

	// Read echo
	response := make([]byte, len(largeData))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("Failed to read large payload: %v", err)
	}

	// Verify
	for i := range response {
		if response[i] != largeData[i] {
			t.Errorf("Large payload mismatch at byte %d: got 0x%02x, want 0x%02x", i, response[i], largeData[i])
			break
		}
	}

	listener.Close()
	wg.Wait()
}

// TestQUICSalamanderConcurrent tests concurrent UDP packet exchanges
func TestQUICSalamanderConcurrent(t *testing.T) {
	secret := []byte("test-concurrent-secret-key-32bit")

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start UDP listener: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockQUICSalamanderServer(serverConn, secret, &wg)

	time.Sleep(100 * time.Millisecond)

	// Create multiple concurrent clients
	numClients := 10
	var clientWg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		clientWg.Add(1)

		go func(clientID int) {
			defer clientWg.Done()

			clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Errorf("Client %d: Failed to create UDP: %v", clientID, err)
				return
			}
			defer clientConn.Close()

			padder := padding.NewSalamanderPadder(secret, padding.Balanced)
			salamanderClient := padding.NewSalamanderPacketConn(clientConn, padder)

			testData := []byte("Client " + string(rune('0'+clientID)) + " data")

			udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				t.Errorf("Client %d: Failed to resolve addr: %v", clientID, err)
				return
			}

			// Send packet
			if _, err := salamanderClient.WriteTo(testData, udpAddr); err != nil {
				t.Errorf("Client %d: Failed to write: %v", clientID, err)
				return
			}

			// Read echo
			response := make([]byte, 65536)
			salamanderClient.SetReadDeadline(time.Now().Add(2 * time.Second))

			n, _, err := salamanderClient.ReadFrom(response)
			if err != nil {
				t.Errorf("Client %d: Failed to read: %v", clientID, err)
				return
			}

			if string(response[:n]) != string(testData) {
				t.Errorf("Client %d: Mismatch: got %q, want %q", clientID, response[:n], testData)
			}
		}(i)
	}

	clientWg.Wait()
	serverConn.Close()
	wg.Wait()
}
