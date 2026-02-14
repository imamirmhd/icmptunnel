package evasion

import (
	"encoding/binary"
)

// AdaptiveSizer dynamically adjusts packet sizes to avoid fixed-size detection.
type AdaptiveSizer struct {
	minSize  int
	maxSize  int
	stepSize int
	current  int
}

// NewAdaptiveSizer creates a new adaptive packet sizer.
func NewAdaptiveSizer(minSize, maxSize, stepSize int) *AdaptiveSizer {
	if minSize < 16 {
		minSize = 16
	}
	if maxSize < minSize {
		maxSize = minSize
	}
	if stepSize < 1 {
		stepSize = 64
	}
	return &AdaptiveSizer{
		minSize:  minSize,
		maxSize:  maxSize,
		stepSize: stepSize,
		current:  minSize,
	}
}

// Resize pads or adjusts data to the current adaptive size.
// Prepends 2 bytes for original data length, then pads to target size.
// Format: [2B original_length][original_data][padding_to_target_size]
func (a *AdaptiveSizer) Resize(data []byte) []byte {
	targetSize := a.nextSize()
	totalNeeded := 2 + len(data)

	if totalNeeded >= targetSize {
		// Data is already larger than target, just prepend length
		result := make([]byte, totalNeeded)
		binary.BigEndian.PutUint16(result[0:2], uint16(len(data)))
		copy(result[2:], data)
		return result
	}

	result := make([]byte, targetSize)
	binary.BigEndian.PutUint16(result[0:2], uint16(len(data)))
	copy(result[2:], data)
	// Remaining bytes are zero-padded
	return result
}

// Unresize extracts the original data from a resized packet.
func (a *AdaptiveSizer) Unresize(data []byte) []byte {
	if len(data) < 2 {
		return data
	}

	originalLen := int(binary.BigEndian.Uint16(data[0:2]))
	if originalLen+2 > len(data) {
		return data // Invalid, return as-is
	}

	result := make([]byte, originalLen)
	copy(result, data[2:2+originalLen])
	return result
}

// nextSize returns the next packet size in the cycling pattern.
func (a *AdaptiveSizer) nextSize() int {
	size := a.current
	a.current += a.stepSize
	if a.current > a.maxSize {
		a.current = a.minSize
	}
	return size
}
