package evasion

import (
	"encoding/binary"
	"fmt"
)

// FragmentHeaderSize is the overhead per fragment.
// Format: [2B fragment_id][1B fragment_index][1B total_fragments]
const FragmentHeaderSize = 4

// Fragmenter handles packet fragmentation and reassembly.
type Fragmenter struct {
	maxFragmentSize int
	nextID          uint16
}

// NewFragmenter creates a new fragmenter.
func NewFragmenter(maxFragmentSize int) *Fragmenter {
	if maxFragmentSize < 32 {
		maxFragmentSize = 32
	}
	return &Fragmenter{maxFragmentSize: maxFragmentSize}
}

// Fragment splits data into fragments, each prefixed with a fragment header.
func (f *Fragmenter) Fragment(data []byte) [][]byte {
	maxPayload := f.maxFragmentSize - FragmentHeaderSize
	if maxPayload <= 0 {
		maxPayload = 1
	}

	totalFragments := (len(data) + maxPayload - 1) / maxPayload
	if totalFragments > 255 {
		totalFragments = 255
	}
	if totalFragments == 0 {
		totalFragments = 1
	}

	f.nextID++
	fragID := f.nextID

	fragments := make([][]byte, 0, totalFragments)
	for i := 0; i < totalFragments; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(data) {
			end = len(data)
		}

		chunk := data[start:end]
		frag := make([]byte, FragmentHeaderSize+len(chunk))
		binary.BigEndian.PutUint16(frag[0:2], fragID)
		frag[2] = byte(i)
		frag[3] = byte(totalFragments)
		copy(frag[FragmentHeaderSize:], chunk)
		fragments = append(fragments, frag)
	}
	return fragments
}

// FragmentBuffer accumulates fragments for reassembly.
type FragmentBuffer struct {
	fragments map[uint16]map[int][]byte
	expected  map[uint16]int
}

// NewFragmentBuffer creates a new fragment buffer.
func NewFragmentBuffer() *FragmentBuffer {
	return &FragmentBuffer{
		fragments: make(map[uint16]map[int][]byte),
		expected:  make(map[uint16]int),
	}
}

// Add adds a fragment to the buffer. Returns reassembled data if all fragments are present.
func (fb *FragmentBuffer) Add(frag []byte) ([]byte, bool, error) {
	if len(frag) < FragmentHeaderSize {
		return nil, false, fmt.Errorf("fragment too small")
	}

	fragID := binary.BigEndian.Uint16(frag[0:2])
	idx := int(frag[2])
	total := int(frag[3])

	if _, ok := fb.fragments[fragID]; !ok {
		fb.fragments[fragID] = make(map[int][]byte)
		fb.expected[fragID] = total
	}

	payload := make([]byte, len(frag)-FragmentHeaderSize)
	copy(payload, frag[FragmentHeaderSize:])
	fb.fragments[fragID][idx] = payload

	if len(fb.fragments[fragID]) == fb.expected[fragID] {
		totalSize := 0
		for _, p := range fb.fragments[fragID] {
			totalSize += len(p)
		}
		result := make([]byte, 0, totalSize)
		for i := 0; i < total; i++ {
			result = append(result, fb.fragments[fragID][i]...)
		}
		delete(fb.fragments, fragID)
		delete(fb.expected, fragID)
		return result, true, nil
	}

	return nil, false, nil
}

// Reassemble combines pre-sorted fragments.
func (f *Fragmenter) Reassemble(fragments [][]byte) ([]byte, error) {
	if len(fragments) == 0 {
		return nil, fmt.Errorf("no fragments to reassemble")
	}

	if len(fragments[0]) < FragmentHeaderSize {
		return nil, fmt.Errorf("fragment too small")
	}

	expectedTotal := int(fragments[0][3])
	if len(fragments) != expectedTotal {
		return nil, fmt.Errorf("expected %d fragments, got %d", expectedTotal, len(fragments))
	}

	sorted := make([][]byte, expectedTotal)
	for _, frag := range fragments {
		if len(frag) < FragmentHeaderSize {
			return nil, fmt.Errorf("fragment too small")
		}
		idx := int(frag[2])
		if idx >= expectedTotal {
			return nil, fmt.Errorf("fragment index %d out of range", idx)
		}
		sorted[idx] = frag[FragmentHeaderSize:]
	}

	totalSize := 0
	for _, piece := range sorted {
		if piece == nil {
			return nil, fmt.Errorf("missing fragment")
		}
		totalSize += len(piece)
	}

	result := make([]byte, 0, totalSize)
	for _, piece := range sorted {
		result = append(result, piece...)
	}
	return result, nil
}
