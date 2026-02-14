// Package evasion provides DPI evasion and firewall bypass techniques.
package evasion

import (
	"time"

	"github.com/user/icmptunnel/config"
)

// Manager coordinates all evasion techniques for packet processing.
type Manager struct {
	fragmenter   *Fragmenter
	padder       *Padder
	jitter       *Jitter
	mimicker     *Mimicker
	checksumMod  *ChecksumManipulator
	adaptiveSizer *AdaptiveSizer
}

// NewManager creates an evasion manager with the given configuration.
func NewManager(cfg config.EvasionConfig) *Manager {
	m := &Manager{}

	if cfg.Fragmentation.Enabled {
		m.fragmenter = NewFragmenter(cfg.Fragmentation.MaxFragmentSize)
	}

	if cfg.Padding.Enabled {
		m.padder = NewPadder(cfg.Padding.MinSize, cfg.Padding.MaxSize)
	}

	if cfg.Jitter.Enabled {
		minDelay, _ := time.ParseDuration(cfg.Jitter.MinDelay)
		maxDelay, _ := time.ParseDuration(cfg.Jitter.MaxDelay)
		if minDelay == 0 {
			minDelay = 10 * time.Millisecond
		}
		if maxDelay == 0 {
			maxDelay = 100 * time.Millisecond
		}
		m.jitter = NewJitter(minDelay, maxDelay)
	}

	if cfg.Mimicry.Enabled {
		m.mimicker = NewMimicker(cfg.Mimicry.OSSignature)
	}

	if cfg.Checksum.Enabled {
		m.checksumMod = NewChecksumManipulator()
	}

	if cfg.AdaptiveSize.Enabled {
		m.adaptiveSizer = NewAdaptiveSizer(cfg.AdaptiveSize.MinSize, cfg.AdaptiveSize.MaxSize, cfg.AdaptiveSize.StepSize)
	}

	return m
}

// Apply processes an outgoing packet through all enabled evasion techniques.
// Returns one or more packets (fragmentation may split into multiple).
func (m *Manager) Apply(packet []byte) ([][]byte, error) {
	data := packet

	// Step 1: Padding
	if m.padder != nil {
		data = m.padder.Pad(data)
	}

	// Step 2: Adaptive sizing
	if m.adaptiveSizer != nil {
		data = m.adaptiveSizer.Resize(data)
	}

	// Step 3: Fragmentation
	var packets [][]byte
	if m.fragmenter != nil {
		frags := m.fragmenter.Fragment(data)
		packets = frags
	} else {
		packets = [][]byte{data}
	}

	return packets, nil
}

// Unapply reverses evasion techniques on received packets.
// Handles defragmentation and padding removal.
func (m *Manager) Unapply(packets [][]byte) ([]byte, error) {
	var data []byte

	// Step 1: Defragment if needed
	if m.fragmenter != nil && len(packets) > 1 {
		var err error
		data, err = m.fragmenter.Reassemble(packets)
		if err != nil {
			return nil, err
		}
	} else if len(packets) > 0 {
		data = packets[0]
	}

	// Step 2: Remove adaptive sizing padding
	if m.adaptiveSizer != nil {
		data = m.adaptiveSizer.Unresize(data)
	}

	// Step 3: Remove padding
	if m.padder != nil {
		var err error
		data, err = m.padder.Unpad(data)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// PreSendDelay returns the jitter delay to apply before sending.
func (m *Manager) PreSendDelay() time.Duration {
	if m.jitter != nil {
		return m.jitter.Delay()
	}
	return 0
}

// GetMimicryConfig returns the mimicry settings if enabled.
func (m *Manager) GetMimicryConfig() *MimicrySettings {
	if m.mimicker != nil {
		return m.mimicker.Settings()
	}
	return nil
}

// ShouldManipulateChecksum returns true if checksum manipulation is enabled.
func (m *Manager) ShouldManipulateChecksum() bool {
	return m.checksumMod != nil
}

// ManipulateChecksum applies checksum manipulation to the ICMP packet.
func (m *Manager) ManipulateChecksum(icmpPacket []byte) []byte {
	if m.checksumMod != nil {
		return m.checksumMod.Manipulate(icmpPacket)
	}
	return icmpPacket
}
