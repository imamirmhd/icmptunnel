package evasion

import (
	"math/rand"
	"sync"
	"time"
)

// TrafficShaper implements burst-based traffic shaping to avoid detection.
// It randomizes burst sizes and inter-burst spacing using exponential distribution.
type TrafficShaper struct {
	burstMin   int
	burstMax   int
	remaining  int
	lastBurst  time.Time
	mu         sync.Mutex
	rng        *rand.Rand
}

// NewTrafficShaper creates a new traffic shaper.
func NewTrafficShaper(burstMin, burstMax int) *TrafficShaper {
	if burstMin < 1 {
		burstMin = 1
	}
	if burstMax < burstMin {
		burstMax = burstMin
	}
	return &TrafficShaper{
		burstMin:  burstMin,
		burstMax:  burstMax,
		remaining: 0,
		lastBurst: time.Now(),
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldSend returns true if a packet can be sent in the current burst.
func (ts *TrafficShaper) ShouldSend() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.remaining > 0 {
		ts.remaining--
		return true
	}

	// Start new burst
	ts.remaining = ts.rng.Intn(ts.burstMax-ts.burstMin+1) + ts.burstMin - 1
	ts.lastBurst = time.Now()
	return true
}

// WaitForBurst adds inter-burst delay with exponential distribution.
func (ts *TrafficShaper) WaitForBurst() {
	ts.mu.Lock()
	if ts.remaining > 0 {
		ts.mu.Unlock()
		return
	}
	// Exponential inter-burst delay: mean = 2ms
	delayMs := ts.rng.ExpFloat64() * 2.0
	if delayMs > 20.0 {
		delayMs = 20.0 // Cap at 20ms
	}
	ts.mu.Unlock()

	time.Sleep(time.Duration(delayMs * float64(time.Millisecond)))
}
