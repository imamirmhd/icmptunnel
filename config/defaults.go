// Package config provides TOML-based configuration for all icmptunnel components.
package config

import "time"

// Default values for ICMP configuration.
const (
	DefaultMaxPacketSize = 1472
	DefaultTTL           = 64
	DefaultReadTimeout   = 5 * time.Second
	DefaultWriteTimeout  = 5 * time.Second
	DefaultSequenceStart = 0
	DefaultIDMin         = 1
	DefaultIDMax         = 65535
	DefaultLogLevel      = "info"
	DefaultLogOutput     = "stdout"
)

// DefaultICMPConfig returns sane default ICMP settings.
func DefaultICMPConfig() ICMPConfig {
	return ICMPConfig{
		MaxPacketSize: DefaultMaxPacketSize,
		TTL:           DefaultTTL,
		ReadTimeout:   "5s",
		WriteTimeout:  "5s",
		SequenceStart: DefaultSequenceStart,
		IDRange:       [2]int{DefaultIDMin, DefaultIDMax},
	}
}

// DefaultEncryptionConfig returns encryption defaults (disabled).
func DefaultEncryptionConfig() EncryptionConfig {
	return EncryptionConfig{
		Enabled: false,
		Method:  "aes-256-gcm",
	}
}

// DefaultEvasionConfig returns all evasion techniques disabled.
func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Fragmentation: FragmentConfig{Enabled: false, MaxFragmentSize: 512},
		Padding:       PaddingConfig{Enabled: false, MinSize: 8, MaxSize: 64},
		Jitter:        JitterConfig{Enabled: false, MinDelay: "10ms", MaxDelay: "100ms"},
		Mimicry:       MimicryConfig{Enabled: false, OSSignature: "linux"},
		Checksum:      ChecksumConfig{Enabled: false},
		AdaptiveSize:  AdaptiveSizeConfig{Enabled: false, MinSize: 64, MaxSize: 1400, StepSize: 64},
	}
}

// DefaultLoggingConfig returns default logging settings.
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:  DefaultLogLevel,
		Output: DefaultLogOutput,
	}
}

// DefaultFirewallConfig returns default firewall settings.
func DefaultFirewallConfig() FirewallConfig {
	return FirewallConfig{
		DisableEchoReply: true,
		EnableForwarding: true,
	}
}
