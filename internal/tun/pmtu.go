package tun

import (
	"encoding/binary"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// DefaultMTU is the default MTU for the TUN interface.
// 1280 is the IPv6 minimum MTU and provides safe margin for all encapsulation overhead.
const DefaultMTU = 1280

// ClampTCPMSS rewrites the MSS option in TCP SYN/SYN-ACK packets
// to fit within the given MTU. This prevents TCP peers from sending
// segments that would be too large for the tunnel.
//
// MSS = MTU - IP header (20) - TCP header (20) = MTU - 40
// For MTU 1280: MSS = 1240
//
// Returns true if MSS was clamped.
func ClampTCPMSS(pkt []byte, mtu int) bool {
	if len(pkt) < 20 {
		return false
	}

	// Check IPv4
	version := pkt[0] >> 4
	if version != 4 {
		return false
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return false
	}

	// Check protocol is TCP (6)
	if pkt[9] != 6 {
		return false
	}

	// Check we have enough for TCP header
	if len(pkt) < ihl+20 {
		return false
	}

	tcpStart := ihl
	flags := pkt[tcpStart+13]

	// Only clamp on SYN or SYN+ACK
	isSYN := (flags & 0x02) != 0
	if !isSYN {
		return false
	}

	// TCP data offset (header length)
	tcpHeaderLen := int(pkt[tcpStart+12]>>4) * 4
	if tcpHeaderLen < 20 || len(pkt) < tcpStart+tcpHeaderLen {
		return false
	}

	// Maximum MSS for this MTU
	maxMSS := uint16(mtu - 40) // IP(20) + TCP(20)

	// Walk TCP options looking for MSS (kind=2, len=4)
	optStart := tcpStart + 20
	optEnd := tcpStart + tcpHeaderLen
	i := optStart
	for i < optEnd {
		kind := pkt[i]
		if kind == 0 { // End of options
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}

		// All other options have length byte
		if i+1 >= optEnd {
			break
		}
		optLen := int(pkt[i+1])
		if optLen < 2 || i+optLen > optEnd {
			break
		}

		if kind == 2 && optLen == 4 { // MSS option
			currentMSS := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			if currentMSS > maxMSS {
				log.Debug("TCP MSS clamped: %d -> %d", currentMSS, maxMSS)
				binary.BigEndian.PutUint16(pkt[i+2:i+4], maxMSS)
				// Recompute TCP checksum
				recomputeTCPChecksum(pkt, tcpStart)
				return true
			}
			return false // MSS already fits
		}

		i += optLen
	}

	return false
}

// recomputeTCPChecksum recalculates the TCP checksum for an IPv4 packet.
func recomputeTCPChecksum(pkt []byte, tcpStart int) {
	if len(pkt) < tcpStart+18 {
		return
	}

	// Clear existing checksum
	pkt[tcpStart+16] = 0
	pkt[tcpStart+17] = 0

	tcpLen := len(pkt) - tcpStart

	// Pseudo-header sum
	var sum uint32
	// Source IP
	sum += uint32(pkt[12])<<8 | uint32(pkt[13])
	sum += uint32(pkt[14])<<8 | uint32(pkt[15])
	// Dest IP
	sum += uint32(pkt[16])<<8 | uint32(pkt[17])
	sum += uint32(pkt[18])<<8 | uint32(pkt[19])
	// Protocol (TCP = 6)
	sum += 6
	// TCP length
	sum += uint32(tcpLen)

	// TCP segment
	for i := tcpStart; i < len(pkt)-1; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if (len(pkt)-tcpStart)%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}

	// Fold carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], checksum)
}

// BuildICMPFragNeeded builds an ICMP Type 3, Code 4 (Fragmentation Needed)
// packet in response to an oversized IP packet.
// nextHopMTU is the MTU to advertise in the ICMP message.
// srcIP is the IP that will be in the ICMP response's source (our TUN IP).
// origPkt is the original packet that was too large.
//
// Returns the complete IP+ICMP packet ready to write to the TUN device.
func BuildICMPFragNeeded(srcIP net.IP, origPkt []byte, nextHopMTU uint16) []byte {
	if len(origPkt) < 20 {
		return nil
	}

	// ICMP payload: original IP header + first 8 bytes of original payload
	origPayloadLen := len(origPkt)
	if origPayloadLen > 28 { // IP header (assumed 20) + 8 bytes
		ihl := int(origPkt[0]&0x0F) * 4
		maxCopy := ihl + 8
		if maxCopy > origPayloadLen {
			maxCopy = origPayloadLen
		}
		origPayloadLen = maxCopy
	}

	// Total: IP(20) + ICMP(8) + original fragment
	totalLen := 20 + 8 + origPayloadLen
	pkt := make([]byte, totalLen)

	// --- IPv4 Header ---
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	// TOS = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// ID, Flags, Fragment offset = 0
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMP

	// Source IP = our TUN IP
	src4 := srcIP.To4()
	if src4 == nil {
		return nil
	}
	copy(pkt[12:16], src4)

	// Dest IP = original packet's source IP
	copy(pkt[16:20], origPkt[12:16])

	// IP header checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	// --- ICMP Header ---
	icmpStart := 20
	pkt[icmpStart] = 3   // Type: Destination Unreachable
	pkt[icmpStart+1] = 4 // Code: Fragmentation Needed
	// Checksum at [icmpStart+2:icmpStart+4] - computed below
	// Unused (2 bytes) = 0
	// Next-Hop MTU (2 bytes)
	binary.BigEndian.PutUint16(pkt[icmpStart+6:icmpStart+8], nextHopMTU)

	// Copy original packet header + 8 bytes
	copy(pkt[icmpStart+8:], origPkt[:origPayloadLen])

	// ICMP checksum
	icmpLen := 8 + origPayloadLen
	var icmpSum uint32
	for i := icmpStart; i < icmpStart+icmpLen-1; i += 2 {
		icmpSum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if icmpLen%2 != 0 {
		icmpSum += uint32(pkt[icmpStart+icmpLen-1]) << 8
	}
	for icmpSum > 0xffff {
		icmpSum = (icmpSum & 0xffff) + (icmpSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[icmpStart+2:icmpStart+4], ^uint16(icmpSum))

	return pkt
}
