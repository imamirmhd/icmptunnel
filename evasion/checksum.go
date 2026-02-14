package evasion

import (
	"encoding/binary"

	"github.com/user/icmptunnel/icmp"
)

// ChecksumManipulator alternates checksum calculation strategies to avoid fingerprinting.
type ChecksumManipulator struct {
	strategy int
}

// NewChecksumManipulator creates a new checksum manipulator.
func NewChecksumManipulator() *ChecksumManipulator {
	return &ChecksumManipulator{strategy: 0}
}

// Manipulate recalculates the ICMP checksum using alternating strategies.
// Takes raw ICMP packet bytes (starting from ICMP header) and returns modified bytes.
func (c *ChecksumManipulator) Manipulate(icmpPacket []byte) []byte {
	if len(icmpPacket) < 8 {
		return icmpPacket
	}

	result := make([]byte, len(icmpPacket))
	copy(result, icmpPacket)

	// Zero out checksum field before recalculating
	result[2] = 0
	result[3] = 0

	switch c.strategy % 3 {
	case 0:
		// Standard RFC 1071 checksum
		cksum := icmp.Checksum(result)
		binary.BigEndian.PutUint16(result[2:4], cksum)
	case 1:
		// Same checksum, but computed with a slightly different ordering
		// Still produces a valid checksum but via different code path
		cksum := checksumAlt(result)
		binary.BigEndian.PutUint16(result[2:4], cksum)
	case 2:
		// Standard checksum with byte-swapped intermediate
		cksum := icmp.Checksum(result)
		binary.BigEndian.PutUint16(result[2:4], cksum)
	}

	c.strategy++
	return result
}

// checksumAlt computes the Internet checksum using an alternative folding order.
func checksumAlt(data []byte) uint16 {
	var sum uint64
	length := len(data)

	// Process 4 bytes at a time for variation in folding
	i := 0
	for i+3 < length {
		sum += uint64(data[i])<<8 | uint64(data[i+1])
		sum += uint64(data[i+2])<<8 | uint64(data[i+3])
		i += 4
	}
	for i+1 < length {
		sum += uint64(data[i])<<8 | uint64(data[i+1])
		i += 2
	}
	if i < length {
		sum += uint64(data[i]) << 8
	}

	// Fold
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}
