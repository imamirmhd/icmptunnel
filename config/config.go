package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ServerConfig holds all server-side configuration.
type ServerConfig struct {
	Listen     string           `toml:"listen"`
	AuthTokens []string         `toml:"auth_tokens"`
	ICMP       ICMPConfig       `toml:"icmp"`
	Encryption EncryptionConfig `toml:"encryption"`
	Evasion    EvasionConfig    `toml:"evasion"`
	Firewall   FirewallConfig   `toml:"firewall"`
	Logging    LoggingConfig    `toml:"logging"`
	Relay      RelayConfig      `toml:"relay"`
}

// ClientConfig holds all client-side configuration.
type ClientConfig struct {
	ServerAddr string           `toml:"server_addr"`
	AuthToken  string           `toml:"auth_token"`
	ICMP       ICMPConfig       `toml:"icmp"`
	Encryption EncryptionConfig `toml:"encryption"`
	Evasion    EvasionConfig    `toml:"evasion"`
	Socks5     []Socks5Config   `toml:"socks5"`
	Forwards   []ForwardConfig  `toml:"forwards"`
	Logging    LoggingConfig    `toml:"logging"`
	Spoof      SpoofConfig      `toml:"spoof"`
}

// RelayServerConfig holds relay server configuration.
type RelayServerConfig struct {
	Listen       string        `toml:"listen"`
	AllowedSources []string    `toml:"allowed_sources"`
	RateLimit    int           `toml:"rate_limit"`
	Logging      LoggingConfig `toml:"logging"`
}

// ICMPConfig holds ICMP-specific settings.
type ICMPConfig struct {
	MaxPacketSize int    `toml:"max_packet_size"`
	TTL           int    `toml:"ttl"`
	ReadTimeout   string `toml:"read_timeout"`
	WriteTimeout  string `toml:"write_timeout"`
	SequenceStart int    `toml:"sequence_start"`
	IDRange       [2]int `toml:"id_range"`
}

// EncryptionConfig holds encryption settings.
type EncryptionConfig struct {
	Enabled bool   `toml:"enabled"`
	Method  string `toml:"method"`
	Key     string `toml:"key"`
}

// EvasionConfig holds all DPI evasion technique settings.
type EvasionConfig struct {
	Fragmentation FragmentConfig     `toml:"fragmentation"`
	Padding       PaddingConfig      `toml:"padding"`
	Jitter        JitterConfig       `toml:"jitter"`
	Mimicry       MimicryConfig      `toml:"mimicry"`
	Checksum      ChecksumConfig     `toml:"checksum"`
	AdaptiveSize  AdaptiveSizeConfig `toml:"adaptive_size"`
}

// FragmentConfig controls packet fragmentation.
type FragmentConfig struct {
	Enabled         bool `toml:"enabled"`
	MaxFragmentSize int  `toml:"max_fragment_size"`
}

// PaddingConfig controls payload randomization/padding.
type PaddingConfig struct {
	Enabled bool `toml:"enabled"`
	MinSize int  `toml:"min_size"`
	MaxSize int  `toml:"max_size"`
}

// JitterConfig controls timing jitter between packets.
type JitterConfig struct {
	Enabled  bool   `toml:"enabled"`
	MinDelay string `toml:"min_delay"`
	MaxDelay string `toml:"max_delay"`
}

// MimicryConfig controls protocol mimicry behavior.
type MimicryConfig struct {
	Enabled     bool   `toml:"enabled"`
	OSSignature string `toml:"os_signature"`
}

// ChecksumConfig controls checksum manipulation.
type ChecksumConfig struct {
	Enabled bool `toml:"enabled"`
}

// AdaptiveSizeConfig controls adaptive packet sizing.
type AdaptiveSizeConfig struct {
	Enabled  bool `toml:"enabled"`
	MinSize  int  `toml:"min_size"`
	MaxSize  int  `toml:"max_size"`
	StepSize int  `toml:"step_size"`
}

// Socks5Config holds SOCKS5 proxy listener settings.
type Socks5Config struct {
	Listen   string `toml:"listen"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// ForwardConfig holds a single port-forwarding rule.
type ForwardConfig struct {
	Listen      string `toml:"listen"`
	Destination string `toml:"destination"`
	Protocol    string `toml:"protocol"`
}

// FirewallConfig holds firewall-related settings.
type FirewallConfig struct {
	DisableEchoReply bool `toml:"disable_echo_reply"`
	EnableForwarding bool `toml:"enable_forwarding"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Output string `toml:"output"`
}

// RelayConfig holds relay/spoofing settings on the server side.
type RelayConfig struct {
	Enabled bool `toml:"enabled"`
}

// SpoofConfig holds ICMP spoofing settings on the client side.
type SpoofConfig struct {
	Enabled       bool   `toml:"enabled"`
	RelayAddr     string `toml:"relay_addr"`
	RouteViaRelay bool   `toml:"route_via_relay"`
}

// LoadServerConfig loads server configuration from a TOML file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{
		Listen:   "0.0.0.0",
		ICMP:     DefaultICMPConfig(),
		Encryption: DefaultEncryptionConfig(),
		Evasion:  DefaultEvasionConfig(),
		Firewall: DefaultFirewallConfig(),
		Logging:  DefaultLoggingConfig(),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := validateServerConfig(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// LoadClientConfig loads client configuration from a TOML file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := &ClientConfig{
		ICMP:       DefaultICMPConfig(),
		Encryption: DefaultEncryptionConfig(),
		Evasion:    DefaultEvasionConfig(),
		Logging:    DefaultLoggingConfig(),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := validateClientConfig(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// LoadRelayConfig loads relay server configuration from a TOML file.
func LoadRelayConfig(path string) (*RelayServerConfig, error) {
	cfg := &RelayServerConfig{
		Listen:    "0.0.0.0",
		RateLimit: 1000,
		Logging:   DefaultLoggingConfig(),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}

func validateServerConfig(cfg *ServerConfig) error {
	if len(cfg.AuthTokens) == 0 {
		return fmt.Errorf("at least one auth_token must be configured")
	}
	if cfg.ICMP.MaxPacketSize < 64 || cfg.ICMP.MaxPacketSize > 65535 {
		return fmt.Errorf("icmp.max_packet_size must be between 64 and 65535")
	}
	if cfg.Encryption.Enabled && cfg.Encryption.Key == "" {
		return fmt.Errorf("encryption.key must be set when encryption is enabled")
	}
	return nil
}

func validateClientConfig(cfg *ClientConfig) error {
	if cfg.ServerAddr == "" && !cfg.Spoof.Enabled {
		return fmt.Errorf("server_addr must be set")
	}
	if cfg.AuthToken == "" {
		return fmt.Errorf("auth_token must be set")
	}
	if len(cfg.Socks5) == 0 && len(cfg.Forwards) == 0 {
		return fmt.Errorf("at least one socks5 or forward rule must be configured")
	}
	if cfg.Encryption.Enabled && cfg.Encryption.Key == "" {
		return fmt.Errorf("encryption.key must be set when encryption is enabled")
	}
	if cfg.Spoof.Enabled && cfg.Spoof.RelayAddr == "" {
		return fmt.Errorf("spoof.relay_addr must be set when spoofing is enabled")
	}
	for i, f := range cfg.Forwards {
		if f.Protocol != "tcp" && f.Protocol != "udp" {
			return fmt.Errorf("forwards[%d].protocol must be 'tcp' or 'udp'", i)
		}
	}
	return nil
}
