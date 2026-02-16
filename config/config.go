package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// ServerConfig holds all configuration for the tunnel server.
type ServerConfig struct {
	Listen     string          `toml:"listen"`
	AuthTokens []string        `toml:"auth_tokens"`
	Logging    LoggingConfig   `toml:"logging"`
	ICMP       ICMPConfig      `toml:"icmp"`
	Transport  TransportConfig `toml:"transport"`
	Encryption EncryptionConfig `toml:"encryption"`
	Evasion    EvasionConfig   `toml:"evasion"`
	Limits     LimitsConfig    `toml:"limits"`
}

// ClientConfig holds all configuration for the tunnel client.
type ClientConfig struct {
	ServerAddr string           `toml:"server_addr"`
	AuthToken  string           `toml:"auth_token"`
	Logging    LoggingConfig    `toml:"logging"`
	ICMP       ICMPConfig       `toml:"icmp"`
	Transport  TransportConfig  `toml:"transport"`
	Encryption EncryptionConfig `toml:"encryption"`
	Evasion    EvasionConfig    `toml:"evasion"`
	Socks5     []Socks5Config   `toml:"socks5"`
	Forwards   []ForwardConfig  `toml:"forward"`
	Spoof      SpoofConfig      `toml:"spoof"`
	Recovery   RecoveryConfig   `toml:"recovery"`
}

// RelayServerConfig holds configuration for the relay server.
type RelayServerConfig struct {
	Listen         string        `toml:"listen"`
	AllowedSources []string      `toml:"allowed_sources"`
	RateLimit      int           `toml:"rate_limit"`
	Logging        LoggingConfig `toml:"logging"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	Output string `toml:"output"`
}

type ICMPConfig struct {
	MaxPacketSize int    `toml:"max_packet_size"`
	SocketBufMB   int    `toml:"socket_buf_mb"`
	ReadTimeout   string `toml:"read_timeout"`
	WriteTimeout  string `toml:"write_timeout"`
}

type TransportConfig struct {
	WindowSize         int    `toml:"window_size"`
	MaxStreams          int    `toml:"max_streams"`
	RetransmitTimeout  string `toml:"retransmit_timeout"`
	HeartbeatInterval  string `toml:"heartbeat_interval"`
	SessionTimeout     string `toml:"session_timeout"`
	Compression        string `toml:"compression"` // "lz4", "zlib", "none"
	SenderWorkers      int    `toml:"sender_workers"`
	AggregationDelay   string `toml:"aggregation_delay"`
	DownlinkReadDeadline string `toml:"downlink_read_deadline"`
	EnableCRC          bool   `toml:"enable_crc"`
}

type EncryptionConfig struct {
	Enabled bool   `toml:"enabled"`
	Method  string `toml:"method"`
	Key     string `toml:"key"`
}

type EvasionConfig struct {
	Enabled         bool   `toml:"enabled"`
	Fragment        bool   `toml:"fragment"`
	FragmentSize    int    `toml:"fragment_size"`
	Padding         bool   `toml:"padding"`
	PaddingMin      int    `toml:"padding_min"`
	PaddingMax      int    `toml:"padding_max"`
	Jitter          bool   `toml:"jitter"`
	JitterMin       string `toml:"jitter_min"`
	JitterMax       string `toml:"jitter_max"`
	Mimicry         string `toml:"mimicry"` // "linux", "windows", "macos"
	AdaptiveSize    bool   `toml:"adaptive_size"`
	AdaptiveMin     int    `toml:"adaptive_min"`
	AdaptiveMax     int    `toml:"adaptive_max"`
	AdaptiveStep    int    `toml:"adaptive_step"`
	ChecksumRotate  bool   `toml:"checksum_rotate"`
	TrafficShaping  bool   `toml:"traffic_shaping"`
	BurstMin        int    `toml:"burst_min"`
	BurstMax        int    `toml:"burst_max"`
}

type Socks5Config struct {
	Listen   string `toml:"listen"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type ForwardConfig struct {
	Listen      string `toml:"listen"`
	Destination string `toml:"destination"`
	Protocol    string `toml:"protocol"` // "tcp" or "udp"
}

type SpoofConfig struct {
	Enabled   bool   `toml:"enabled"`
	RelayAddr string `toml:"relay_addr"`
	SourceIP  string `toml:"source_ip"`
}

type LimitsConfig struct {
	MaxSessions       int `toml:"max_sessions"`
	MaxStreamsPerSession int `toml:"max_streams_per_session"`
	MaxPPS            int `toml:"max_pps"`
}

type RecoveryConfig struct {
	Enabled           bool   `toml:"enabled"`
	MaxReconnects     int    `toml:"max_reconnects"`
	ReconnectDelay    string `toml:"reconnect_delay"`
	MaxReconnectDelay string `toml:"max_reconnect_delay"`
	BufferReplay      bool   `toml:"buffer_replay"`
	ReplayBufferSize  int    `toml:"replay_buffer_size"`
}

// LoadServerConfig loads server configuration from a TOML file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &ServerConfig{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyServerDefaults(cfg)
	return cfg, nil
}

// LoadClientConfig loads client configuration from a TOML file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &ClientConfig{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyClientDefaults(cfg)
	return cfg, nil
}

// LoadRelayConfig loads relay server configuration from a TOML file.
func LoadRelayConfig(path string) (*RelayServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &RelayServerConfig{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 10000
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}

	return cfg, nil
}

func applyServerDefaults(cfg *ServerConfig) {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	applyICMPDefaults(&cfg.ICMP)
	applyTransportDefaults(&cfg.Transport)
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Limits.MaxSessions == 0 {
		cfg.Limits.MaxSessions = 10000
	}
	if cfg.Limits.MaxStreamsPerSession == 0 {
		cfg.Limits.MaxStreamsPerSession = 4096
	}
	if cfg.Limits.MaxPPS == 0 {
		cfg.Limits.MaxPPS = 100000
	}
}

func applyClientDefaults(cfg *ClientConfig) {
	applyICMPDefaults(&cfg.ICMP)
	applyTransportDefaults(&cfg.Transport)
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Recovery.MaxReconnects == 0 {
		cfg.Recovery.MaxReconnects = 100
	}
	if cfg.Recovery.ReconnectDelay == "" {
		cfg.Recovery.ReconnectDelay = "100ms"
	}
	if cfg.Recovery.MaxReconnectDelay == "" {
		cfg.Recovery.MaxReconnectDelay = "30s"
	}
	if cfg.Recovery.ReplayBufferSize == 0 {
		cfg.Recovery.ReplayBufferSize = 65536
	}
}

func applyICMPDefaults(cfg *ICMPConfig) {
	if cfg.MaxPacketSize == 0 {
		cfg.MaxPacketSize = DefaultMaxPacketSize
	}
	if cfg.SocketBufMB == 0 {
		cfg.SocketBufMB = DefaultSocketBufMB
	}
	if cfg.ReadTimeout == "" {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout == "" {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
}

func applyTransportDefaults(cfg *TransportConfig) {
	if cfg.WindowSize == 0 {
		cfg.WindowSize = DefaultWindowSize
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	if cfg.RetransmitTimeout == "" {
		cfg.RetransmitTimeout = DefaultRetransmitTimeout
	}
	if cfg.HeartbeatInterval == "" {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.SessionTimeout == "" {
		cfg.SessionTimeout = DefaultSessionTimeout
	}
	if cfg.Compression == "" {
		cfg.Compression = DefaultCompression
	}
	if cfg.SenderWorkers == 0 {
		cfg.SenderWorkers = DefaultSenderWorkers
	}
	if cfg.AggregationDelay == "" {
		cfg.AggregationDelay = DefaultAggregationDelay
	}
	if cfg.DownlinkReadDeadline == "" {
		cfg.DownlinkReadDeadline = DefaultDownlinkReadDeadline
	}
}

// ParseDuration parses a duration string with fallback.
func ParseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
