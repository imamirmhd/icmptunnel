package evasion

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
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
		minSize: minSize, maxSize: maxSize, stepSize: stepSize, current: minSize,
	}
}

// Resize pads or adjusts data to the current adaptive size.
func (a *AdaptiveSizer) Resize(data []byte) []byte {
	targetSize := a.nextSize()
	totalNeeded := 2 + len(data)

	if totalNeeded >= targetSize {
		result := make([]byte, totalNeeded)
		binary.BigEndian.PutUint16(result[0:2], uint16(len(data)))
		copy(result[2:], data)
		return result
	}

	result := make([]byte, targetSize)
	binary.BigEndian.PutUint16(result[0:2], uint16(len(data)))
	copy(result[2:], data)
	return result
}

// Unresize extracts the original data from a resized packet.
func (a *AdaptiveSizer) Unresize(data []byte) []byte {
	if len(data) < 2 {
		return data
	}

	originalLen := int(binary.BigEndian.Uint16(data[0:2]))
	if originalLen+2 > len(data) {
		return data
	}

	result := make([]byte, originalLen)
	copy(result, data[2:2+originalLen])
	return result
}

func (a *AdaptiveSizer) nextSize() int {
	size := a.current
	a.current += a.stepSize
	if a.current > a.maxSize {
		a.current = a.minSize
	}
	return size
}

// Padder adds random padding to payloads.
type Padder struct {
	minSize int
	maxSize int
}

// NewPadder creates a new padder with configurable padding range.
func NewPadder(minSize, maxSize int) *Padder {
	if minSize < 1 {
		minSize = 1
	}
	if maxSize < minSize {
		maxSize = minSize
	}
	if maxSize > 255 {
		maxSize = 255
	}
	return &Padder{minSize: minSize, maxSize: maxSize}
}

// Pad adds random padding to the data.
// Format: [original_data][random_padding_bytes][1B padding_length]
func (p *Padder) Pad(data []byte) []byte {
	padLen := p.randomPadLength()
	result := make([]byte, len(data)+padLen+1)
	copy(result, data)

	padding := make([]byte, padLen)
	rand.Read(padding)
	copy(result[len(data):], padding)
	result[len(result)-1] = byte(padLen)

	return result
}

// Unpad removes padding from the data.
func (p *Padder) Unpad(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short to unpad")
	}

	padLen := int(data[len(data)-1])
	originalLen := len(data) - padLen - 1

	if originalLen < 0 {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}

	result := make([]byte, originalLen)
	copy(result, data[:originalLen])
	return result, nil
}

func (p *Padder) randomPadLength() int {
	if p.minSize == p.maxSize {
		return p.minSize
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(p.maxSize-p.minSize+1)))
	return p.minSize + int(n.Int64())
}
