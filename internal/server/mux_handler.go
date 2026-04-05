package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/mux"
)

// MuxHandler handles multiplexed connections using smux protocol
// Accepts streams from mux connections and relays them to targets
type MuxHandler struct {
	config   *mux.Config
	srvCtx   *serverContext
	logger   *log.Logger
	clientID string

	// Stats
	activeStreams int64
	totalStreams  int64
	bytesUp       int64
	bytesDown     int64
}

// NewMuxHandler creates a new mux handler
func NewMuxHandler(srvCtx *serverContext, config *mux.Config, clientID string) *MuxHandler {
	if config == nil {
		config = mux.DefaultConfig()
	}
	return &MuxHandler{
		config:   config,
		srvCtx:   srvCtx,
		logger:   log.WithPrefix("mux-handler"),
		clientID: clientID,
	}
}

// CanHandle determines if the connection is using smux protocol
// SMUX frame format: VERSION(1B) | CMD(1B) | LENGTH(2B) | STREAMID(4B) | DATA(LENGTH)
// VERSION: 1 or 2
// CMD: 0=SYN, 1=FIN, 2=PSH, 3=NOP, 4=UPD (v2 only)
func (h *MuxHandler) CanHandle(conn net.Conn, firstBytes []byte) bool {
	if len(firstBytes) < 2 {
		return false
	}

	version := firstBytes[0]
	cmd := firstBytes[1]

	// Check for valid smux version (1 or 2)
	if version != 1 && version != 2 {
		return false
	}

	// Check for valid smux command
	// cmdSYN=0, cmdFIN=1, cmdPSH=2, cmdNOP=3, cmdUPD=4 (v2 only)
	maxCmd := byte(3)
	if version == 2 {
		maxCmd = 4
	}

	if cmd > maxCmd {
		return false
	}

	// First frame from client should typically be SYN (0) or NOP (3 - keepalive)
	// Accept any valid command for flexibility
	h.logger.Debug("Detected smux protocol (version=%d, cmd=%d)", version, cmd)
	return true
}

// Handle accepts streams from the mux connection and processes them
func (h *MuxHandler) Handle(ctx context.Context, conn net.Conn) error {
	// Create mux server session
	muxServer, err := mux.NewServer(conn, h.config)
	if err != nil {
		h.logger.Error("Failed to create mux server: %v", err)
		return fmt.Errorf("mux server creation failed: %w", err)
	}
	defer muxServer.Close()

	h.logger.Info("Mux session established (clientID=%s)", h.clientID)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Accept and handle streams
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("Mux handler context done, closing session")
			return ctx.Err()
		default:
		}

		// Accept next stream with timeout
		stream, err := muxServer.AcceptStream()
		if err != nil {
			if muxServer.IsClosed() {
				h.logger.Debug("Mux session closed")
				break
			}
			h.logger.Debug("Accept stream error: %v", err)
			break
		}

		atomic.AddInt64(&h.activeStreams, 1)
		atomic.AddInt64(&h.totalStreams, 1)

		wg.Add(1)
		go func(stream net.Conn) {
			defer wg.Done()
			defer atomic.AddInt64(&h.activeStreams, -1)
			defer stream.Close()

			h.handleStream(ctx, stream)
		}(stream)
	}

	// Wait for all streams to finish
	wg.Wait()

	h.logger.Info("Mux session closed (total_streams=%d, bytes_up=%d, bytes_down=%d)",
		atomic.LoadInt64(&h.totalStreams),
		atomic.LoadInt64(&h.bytesUp),
		atomic.LoadInt64(&h.bytesDown))

	return nil
}

// handleStream processes a single multiplexed stream
// Protocol: [2B addr_len][addr][data...]
func (h *MuxHandler) handleStream(ctx context.Context, stream net.Conn) {
	streamLogger := log.WithPrefix(fmt.Sprintf("mux-stream:%s", h.clientID))

	// Set initial read deadline
	stream.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read target address
	// Format: [2B length (big endian)][address string]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		streamLogger.Debug("Failed to read address length: %v", err)
		return
	}

	addrLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if addrLen < 3 || addrLen > 256 {
		streamLogger.Debug("Invalid address length: %d", addrLen)
		return
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		streamLogger.Debug("Failed to read address: %v", err)
		return
	}

	targetAddr := string(addrBuf)
	streamLogger.Debug("Stream target: %s", targetAddr)

	// Connect to target
	var targetConn net.Conn
	var err error

	if h.srvCtx.upstreamDialer != nil {
		// Multi-hop mode: dial through upstream
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		targetConn, err = h.srvCtx.upstreamDialer.Dial(dialCtx, targetAddr)
		cancel()
	} else {
		// Direct mode: dial target directly
		targetConn, err = optimizedDial("tcp", targetAddr, 10*time.Second)
	}

	if err != nil {
		streamLogger.Debug("Failed to connect to %s: %v", targetAddr, err)
		// Send failure response: [0x01]
		stream.Write([]byte{0x01})
		return
	}
	defer targetConn.Close()

	// Send success response: [0x00]
	stream.Write([]byte{0x00})

	// Clear deadline for relay
	stream.SetReadDeadline(time.Time{})

	streamLogger.Debug("Connected to %s, starting relay", targetAddr)

	// Bidirectional relay
	bytesUp, bytesDown := h.relay(stream, targetConn)

	// Update stats
	atomic.AddInt64(&h.bytesUp, bytesUp)
	atomic.AddInt64(&h.bytesDown, bytesDown)

	// Update metrics
	if h.srvCtx.metrics != nil {
		h.srvCtx.metrics.AddBytes(bytesUp, bytesDown)
	}

	// Update per-client metrics
	if h.srvCtx.registry != nil && h.clientID != "" {
		h.srvCtx.registry.AddBytes(h.clientID, bytesUp, bytesDown)
	}

	streamLogger.Debug("Relay closed: up=%d down=%d", bytesUp, bytesDown)
}

// relay copies data bidirectionally between stream and target
func (h *MuxHandler) relay(stream, target net.Conn) (bytesUp, bytesDown int64) {
	var wg sync.WaitGroup
	var up, down int64

	wg.Add(2)

	// Stream -> Target (upload)
	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(target, stream)
		atomic.StoreInt64(&up, n)
		// Close write side of target to signal EOF
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Stream (download)
	go func() {
		defer wg.Done()
		n, _ := optimizedRelay(stream, target)
		atomic.StoreInt64(&down, n)
	}()

	wg.Wait()
	return atomic.LoadInt64(&up), atomic.LoadInt64(&down)
}

// Stats returns current handler statistics
func (h *MuxHandler) Stats() (activeStreams, totalStreams, bytesUp, bytesDown int64) {
	return atomic.LoadInt64(&h.activeStreams),
		atomic.LoadInt64(&h.totalStreams),
		atomic.LoadInt64(&h.bytesUp),
		atomic.LoadInt64(&h.bytesDown)
}

// Handler interface for protocol detection pattern
type Handler interface {
	CanHandle(conn net.Conn, firstBytes []byte) bool
	Handle(ctx context.Context, conn net.Conn) error
}

// Ensure MuxHandler implements Handler interface
var _ Handler = (*MuxHandler)(nil)
