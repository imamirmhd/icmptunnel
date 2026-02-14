package evasion

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Jitter adds random timing delays between packet transmissions.
type Jitter struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewJitter creates a new jitter generator.
func NewJitter(minDelay, maxDelay time.Duration) *Jitter {
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	return &Jitter{minDelay: minDelay, maxDelay: maxDelay}
}

// Delay returns a random duration between minDelay and maxDelay.
func (j *Jitter) Delay() time.Duration {
	if j.minDelay == j.maxDelay {
		return j.minDelay
	}
	rangeNs := j.maxDelay.Nanoseconds() - j.minDelay.Nanoseconds()
	n, _ := rand.Int(rand.Reader, big.NewInt(rangeNs))
	return j.minDelay + time.Duration(n.Int64())
}

// Sleep applies a random jitter delay.
func (j *Jitter) Sleep() {
	d := j.Delay()
	if d > 0 {
		time.Sleep(d)
	}
}
