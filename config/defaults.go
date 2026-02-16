package config

// Default values for all configuration parameters.
const (
	DefaultMaxPacketSize = 1472
	DefaultSocketBufMB   = 32
	DefaultReadTimeout   = "5s"
	DefaultWriteTimeout  = "5s"

	DefaultWindowSize         = 2048
	DefaultMaxStreams          = 4096
	DefaultRetransmitTimeout  = "100ms"
	DefaultHeartbeatInterval  = "5s"
	DefaultSessionTimeout     = "60s"
	DefaultCompression        = "lz4"
	DefaultSenderWorkers      = 4
	DefaultAggregationDelay   = "500us"
	DefaultDownlinkReadDeadline = "10ms"
)
