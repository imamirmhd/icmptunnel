// Package evasion provides DPI evasion and traffic obfuscation techniques.
package evasion

import (
	"time"

	"github.com/imamirmhd/icmptunnel/config"
)

// Manager orchestrates all evasion techniques.
type Manager struct {
	fragmenter    *Fragmenter
	padder        *Padder
	jitter        *Jitter
	mimicker      *Mimicker
	adaptiveSizer *AdaptiveSizer
	checksumManip *ChecksumManipulator
	shaper        *TrafficShaper
	enabled       bool
	cfg           config.EvasionConfig
}

// NewManager creates a new evasion manager.
func NewManager(cfg config.EvasionConfig) *Manager {
	m := &Manager{
		enabled: cfg.Enabled,
		cfg:     cfg,
	}

	if !cfg.Enabled {
		return m
	}

	if cfg.Fragment {
		fragSize := cfg.FragmentSize
		if fragSize == 0 {
			fragSize = 256
		}
		m.fragmenter = NewFragmenter(fragSize)
	}

	if cfg.Padding {
		m.padder = NewPadder(cfg.PaddingMin, cfg.PaddingMax)
	}

	if cfg.Jitter {
		minDelay, _ := time.ParseDuration(cfg.JitterMin)
		maxDelay, _ := time.ParseDuration(cfg.JitterMax)
		if minDelay == 0 {
			minDelay = 1 * time.Millisecond
		}
		if maxDelay == 0 {
			maxDelay = 10 * time.Millisecond
		}
		m.jitter = NewJitter(minDelay, maxDelay)
	}

	if cfg.Mimicry != "" {
		m.mimicker = NewMimicker(cfg.Mimicry)
	}

	if cfg.AdaptiveSize {
		m.adaptiveSizer = NewAdaptiveSizer(cfg.AdaptiveMin, cfg.AdaptiveMax, cfg.AdaptiveStep)
	}

	if cfg.ChecksumRotate {
		m.checksumManip = NewChecksumManipulator()
	}

	if cfg.TrafficShaping {
		burstMin := cfg.BurstMin
		burstMax := cfg.BurstMax
		if burstMin == 0 {
			burstMin = 1
		}
		if burstMax == 0 {
			burstMax = 8
		}
		m.shaper = NewTrafficShaper(burstMin, burstMax)
	}

	return m
}

// ApplyOutbound applies all enabled evasion techniques to outbound data.
func (m *Manager) ApplyOutbound(data []byte) []byte {
	if !m.enabled || len(data) == 0 {
		return data
	}

	result := data

	if m.padder != nil {
		result = m.padder.Pad(result)
	}

	if m.adaptiveSizer != nil {
		result = m.adaptiveSizer.Resize(result)
	}

	return result
}

// RemoveInbound reverses all evasion techniques from inbound data.
func (m *Manager) RemoveInbound(data []byte) ([]byte, error) {
	if !m.enabled || len(data) == 0 {
		return data, nil
	}

	result := data

	if m.adaptiveSizer != nil {
		result = m.adaptiveSizer.Unresize(result)
	}

	if m.padder != nil {
		var err error
		result, err = m.padder.Unpad(result)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Fragment splits data into fragments if fragmentation is enabled.
func (m *Manager) Fragment(data []byte) [][]byte {
	if !m.enabled || m.fragmenter == nil {
		return [][]byte{data}
	}
	return m.fragmenter.Fragment(data)
}

// Fragmenter returns the fragmenter, if any.
func (m *Manager) Fragmenter() *Fragmenter {
	return m.fragmenter
}

// FragmentBuffer returns a new fragment buffer for reassembly.
func (m *Manager) NewFragmentBuffer() *FragmentBuffer {
	return NewFragmentBuffer()
}

// ApplyJitter applies timing jitter if enabled.
func (m *Manager) ApplyJitter() {
	if m.enabled && m.jitter != nil {
		m.jitter.Sleep()
	}
}

// GetMimicrySettings returns the mimicry settings, if any.
func (m *Manager) GetMimicrySettings() *MimicrySettings {
	if m.mimicker != nil {
		return m.mimicker.Settings()
	}
	return nil
}

// ApplyMimicry applies mimicry to ICMP headers.
func (m *Manager) ApplyMimicry(icmpPacket []byte, seqCounter uint16) {
	if m.enabled && m.mimicker != nil {
		m.mimicker.ApplyToHeaders(icmpPacket, seqCounter)
	}
}

// ManipulateChecksum applies checksum manipulation.
func (m *Manager) ManipulateChecksum(icmpPacket []byte) []byte {
	if m.enabled && m.checksumManip != nil {
		return m.checksumManip.Manipulate(icmpPacket)
	}
	return icmpPacket
}

// ShouldSendNow checks if the traffic shaper allows sending.
func (m *Manager) ShouldSendNow() bool {
	if !m.enabled || m.shaper == nil {
		return true
	}
	return m.shaper.ShouldSend()
}

// WaitForBurst blocks until the shaper allows a burst.
func (m *Manager) WaitForBurst() {
	if m.enabled && m.shaper != nil {
		m.shaper.WaitForBurst()
	}
}

// IsEnabled returns whether evasion is enabled.
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// IsFragmentEnabled returns whether fragmentation is enabled.
func (m *Manager) IsFragmentEnabled() bool {
	return m.enabled && m.fragmenter != nil
}
