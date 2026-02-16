package evasion

import (
	"encoding/binary"

	"github.com/imamirmhd/icmptunnel/icmp"
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
func (c *ChecksumManipulator) Manipulate(icmpPacket []byte) []byte {
	if len(icmpPacket) < 8 {
		return icmpPacket
	}

	result := make([]byte, len(icmpPacket))
	copy(result, icmpPacket)

	// Zero out checksum before recalculating
	result[2] = 0
	result[3] = 0

	cksum := icmp.Checksum(result)
	binary.BigEndian.PutUint16(result[2:4], cksum)

	c.strategy++
	return result
}
