package multiport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// PortRange represents a contiguous range of UDP ports allocated to a client
type PortRange struct {
	Start int
	Count int
}

// PortAllocator manages port range allocation for multiple clients
type PortAllocator struct {
	mu sync.Mutex

	// Configuration
	basePort   int // Starting port for allocations (e.g., 50000)
	portCount  int // Total ports available per client (e.g., 500)
	maxClients int // Maximum concurrent clients

	// State
	allocated map[string]*Allocation // sessionID -> allocation
	portUsage []bool                 // bitmap of used ports
}

// Allocation represents an allocated port range for a client
type Allocation struct {
	SessionID string
	PortRange PortRange
	Secret    []byte // Shared secret for HMAC
}

// NewPortAllocator creates a new port allocator
// basePort: starting port (e.g., 50000)
// portCount: ports per client (e.g., 500)
// maxClients: maximum concurrent clients (e.g., 10)
func NewPortAllocator(basePort, portCount, maxClients int) *PortAllocator {
	totalPorts := portCount * maxClients
	return &PortAllocator{
		basePort:   basePort,
		portCount:  portCount,
		maxClients: maxClients,
		allocated:  make(map[string]*Allocation),
		portUsage:  make([]bool, totalPorts),
	}
}

// Allocate allocates a port range for a new client
// Returns the allocation with session ID, port range, and shared secret
func (pa *PortAllocator) Allocate(clientID string) (*Allocation, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Find a free range
	startIdx := pa.findFreeRange()
	if startIdx == -1 {
		return nil, fmt.Errorf("no free port ranges available (max clients: %d)", pa.maxClients)
	}

	// Generate session ID
	sessionID := uuid.New().String()

	// Generate shared secret (32 bytes for HMAC-SHA256)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}

	// Create allocation
	alloc := &Allocation{
		SessionID: sessionID,
		PortRange: PortRange{
			Start: pa.basePort + startIdx,
			Count: pa.portCount,
		},
		Secret: secret,
	}

	// Mark ports as used
	for i := 0; i < pa.portCount; i++ {
		pa.portUsage[startIdx+i] = true
	}

	// Store allocation
	pa.allocated[sessionID] = alloc

	return alloc, nil
}

// findFreeRange finds a contiguous free range of ports
// Returns the starting index in portUsage array, or -1 if not found
func (pa *PortAllocator) findFreeRange() int {
	for start := 0; start <= len(pa.portUsage)-pa.portCount; start += pa.portCount {
		// Check if this range is free
		free := true
		for i := 0; i < pa.portCount; i++ {
			if pa.portUsage[start+i] {
				free = false
				break
			}
		}
		if free {
			return start
		}
	}
	return -1
}

// Release releases a port range allocation
func (pa *PortAllocator) Release(sessionID string) error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	alloc, exists := pa.allocated[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Mark ports as free
	startIdx := alloc.PortRange.Start - pa.basePort
	for i := 0; i < alloc.PortRange.Count; i++ {
		pa.portUsage[startIdx+i] = false
	}

	// Remove allocation
	delete(pa.allocated, sessionID)

	return nil
}

// GetAllocation retrieves an allocation by session ID
func (pa *PortAllocator) GetAllocation(sessionID string) (*Allocation, bool) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	alloc, exists := pa.allocated[sessionID]
	return alloc, exists
}

// Stats returns current allocator statistics
type AllocatorStats struct {
	ActiveSessions int
	TotalPorts     int
	UsedPorts      int
	FreeRanges     int
}

// Stats returns current allocator statistics
func (pa *PortAllocator) Stats() AllocatorStats {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	usedPorts := 0
	for _, used := range pa.portUsage {
		if used {
			usedPorts++
		}
	}

	// Count free ranges
	freeRanges := 0
	for start := 0; start <= len(pa.portUsage)-pa.portCount; start += pa.portCount {
		free := true
		for i := 0; i < pa.portCount; i++ {
			if pa.portUsage[start+i] {
				free = false
				break
			}
		}
		if free {
			freeRanges++
		}
	}

	return AllocatorStats{
		ActiveSessions: len(pa.allocated),
		TotalPorts:     len(pa.portUsage),
		UsedPorts:      usedPorts,
		FreeRanges:     freeRanges,
	}
}

// SecretHex returns the secret as hex-encoded string (for JSON serialization)
func (a *Allocation) SecretHex() string {
	return hex.EncodeToString(a.Secret)
}
