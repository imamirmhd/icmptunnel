package evasion

import (
	"math/rand"
	"time"
)

// Jitter adds random timing delays between packet transmissions.
// Uses math/rand for performance (jitter doesn't need CSPRNG).
type Jitter struct {
	minDelay time.Duration
	maxDelay time.Duration
	rng      *rand.Rand
}

// NewJitter creates a new jitter generator.
func NewJitter(minDelay, maxDelay time.Duration) *Jitter {
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	return &Jitter{
		minDelay: minDelay,
		maxDelay: maxDelay,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Delay returns a random duration between minDelay and maxDelay.
func (j *Jitter) Delay() time.Duration {
	if j.minDelay == j.maxDelay {
		return j.minDelay
	}
	rangeNs := j.maxDelay.Nanoseconds() - j.minDelay.Nanoseconds()
	return j.minDelay + time.Duration(j.rng.Int63n(rangeNs))
}

// Sleep applies a random jitter delay.
func (j *Jitter) Sleep() {
	d := j.Delay()
	if d > 0 {
		time.Sleep(d)
	}
}
