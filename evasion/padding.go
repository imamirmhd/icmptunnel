package evasion

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Padder adds random padding to payloads to defeat fixed-size pattern detection.
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
		maxSize = 255 // Padding length must fit in one byte
	}
	return &Padder{minSize: minSize, maxSize: maxSize}
}

// Pad adds random padding to the data.
// Format: [original_data][random_padding_bytes][1B padding_length]
func (p *Padder) Pad(data []byte) []byte {
	padLen := p.randomPadLength()
	result := make([]byte, len(data)+padLen+1)
	copy(result, data)

	// Fill padding with random bytes
	padding := make([]byte, padLen)
	rand.Read(padding)
	copy(result[len(data):], padding)

	// Last byte encodes the padding length
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
		return nil, fmt.Errorf("invalid padding length: %d (data length: %d)", padLen, len(data))
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
