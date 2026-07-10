//go:build !linux

package strategy

// tryStartPacketOverlap is a no-op off Linux: packet-level seqovl needs NFQUEUE
// and a raw socket, neither of which exists on Android / macOS / Windows. The
// connection rides the level-B app-framing decoy alone.
func (s *SeqovlStrategy) tryStartPacketOverlap() bool {
	return false
}
