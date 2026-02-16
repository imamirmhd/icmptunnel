package icmp

import (
	"fmt"
	"net"
)

// SpoofHeaderSize is the size of the spoof metadata header embedded in the payload.
// Format: [4B real_client_ip][1B route_flag][4B relay_ip]
const SpoofHeaderSize = 9

// RouteFlag values for spoofed packet routing.
const (
	RouteDirect   uint8 = 0 // Server responds directly to client
	RouteViaRelay uint8 = 1 // Server responds via relay
)

// SpoofHeader contains metadata embedded in spoofed ICMP packets.
type SpoofHeader struct {
	RealClientIP net.IP
	RouteFlag    uint8
	RelayIP      net.IP
}

// EncodeSpoofHeader serializes a SpoofHeader into bytes.
func EncodeSpoofHeader(h *SpoofHeader) []byte {
	buf := make([]byte, SpoofHeaderSize)
	ip4 := h.RealClientIP.To4()
	if ip4 == nil {
		ip4 = make([]byte, 4)
	}
	copy(buf[0:4], ip4)
	buf[4] = h.RouteFlag
	relay4 := h.RelayIP.To4()
	if relay4 == nil {
		relay4 = make([]byte, 4)
	}
	copy(buf[5:9], relay4)
	return buf
}

// DecodeSpoofHeader deserializes a SpoofHeader from bytes.
func DecodeSpoofHeader(data []byte) (*SpoofHeader, error) {
	if len(data) < SpoofHeaderSize {
		return nil, fmt.Errorf("spoof header too short: %d bytes", len(data))
	}
	return &SpoofHeader{
		RealClientIP: net.IP(data[0:4]),
		RouteFlag:    data[4],
		RelayIP:      net.IP(data[5:9]),
	}, nil
}

// PrependSpoofHeader prepends spoof metadata to a payload.
func PrependSpoofHeader(payload []byte, h *SpoofHeader) []byte {
	header := EncodeSpoofHeader(h)
	result := make([]byte, SpoofHeaderSize+len(payload))
	copy(result, header)
	copy(result[SpoofHeaderSize:], payload)
	return result
}

// ExtractSpoofHeader extracts and removes the spoof header from a payload.
func ExtractSpoofHeader(payload []byte) (*SpoofHeader, []byte, error) {
	if len(payload) < SpoofHeaderSize {
		return nil, nil, fmt.Errorf("payload too short for spoof header")
	}
	header, err := DecodeSpoofHeader(payload[:SpoofHeaderSize])
	if err != nil {
		return nil, nil, err
	}
	return header, payload[SpoofHeaderSize:], nil
}
