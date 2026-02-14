package icmp

import (
	"encoding/binary"
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
	RealClientIP net.IP // The actual client IP address
	RouteFlag    uint8  // How the server should respond
	RelayIP      net.IP // The relay server IP address
}

// EncodeSpoofHeader serializes a SpoofHeader into bytes.
func EncodeSpoofHeader(h *SpoofHeader) ([]byte, error) {
	clientIP := h.RealClientIP.To4()
	relayIP := h.RelayIP.To4()
	if clientIP == nil || relayIP == nil {
		return nil, fmt.Errorf("IPv4 addresses required for spoof header")
	}

	buf := make([]byte, SpoofHeaderSize)
	copy(buf[0:4], clientIP)
	buf[4] = h.RouteFlag
	copy(buf[5:9], relayIP)
	return buf, nil
}

// DecodeSpoofHeader deserializes bytes into a SpoofHeader.
func DecodeSpoofHeader(data []byte) (*SpoofHeader, error) {
	if len(data) < SpoofHeaderSize {
		return nil, fmt.Errorf("data too short for spoof header: %d bytes", len(data))
	}

	return &SpoofHeader{
		RealClientIP: net.IPv4(data[0], data[1], data[2], data[3]),
		RouteFlag:    data[4],
		RelayIP:      net.IPv4(data[5], data[6], data[7], data[8]),
	}, nil
}

// BuildSpoofedPayload wraps tunnel data with a spoof header.
// The resulting payload contains the spoof header followed by the tunnel packet.
func BuildSpoofedPayload(header *SpoofHeader, tunnelData []byte) ([]byte, error) {
	hdrBytes, err := EncodeSpoofHeader(header)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, len(hdrBytes)+len(tunnelData))
	copy(payload[0:], hdrBytes)
	copy(payload[SpoofHeaderSize:], tunnelData)
	return payload, nil
}

// ExtractSpoofedPayload separates the spoof header from the tunnel data.
func ExtractSpoofedPayload(payload []byte) (*SpoofHeader, []byte, error) {
	if len(payload) < SpoofHeaderSize {
		return nil, nil, fmt.Errorf("payload too short for spoof header")
	}

	header, err := DecodeSpoofHeader(payload[:SpoofHeaderSize])
	if err != nil {
		return nil, nil, err
	}

	tunnelData := payload[SpoofHeaderSize:]
	return header, tunnelData, nil
}

// StreamDataHeader wraps stream data with a stream ID.
// Wire format: [2B stream_id][NB data]
const StreamDataHeaderSize = 2

// EncodeStreamData wraps data with a stream ID for multiplexing.
func EncodeStreamData(streamID uint16, data []byte) []byte {
	buf := make([]byte, StreamDataHeaderSize+len(data))
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	copy(buf[2:], data)
	return buf
}

// DecodeStreamData extracts the stream ID and data.
func DecodeStreamData(payload []byte) (streamID uint16, data []byte, err error) {
	if len(payload) < StreamDataHeaderSize {
		return 0, nil, fmt.Errorf("stream data too short")
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	data = payload[2:]
	return streamID, data, nil
}
