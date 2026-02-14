package icmp

import (
	"encoding/binary"
	"fmt"
)

// Packet type constants for the tunnel protocol.
const (
	TypeData    uint8 = 0x00
	TypeAuth    uint8 = 0x01
	TypeControl uint8 = 0x02
	TypeDiag    uint8 = 0x03
)

// Flag bit positions.
const (
	FlagEncrypted uint8 = 1 << 3
	FlagAuth      uint8 = 1 << 4
	FlagSpoof     uint8 = 1 << 5
	FlagFragment  uint8 = 1 << 2
	FlagCompressed uint8 = 1 << 6
)

// Control subtypes.
const (
	ControlHeartbeat  uint8 = 0x01
	ControlClose      uint8 = 0x02
	ControlAuthOK     uint8 = 0x03
	ControlAuthFail   uint8 = 0x04
	ControlConnect    uint8 = 0x05
	ControlConnectACK uint8 = 0x06
	ControlConnectFail uint8 = 0x07
	ControlACK        uint8 = 0x08
	ControlSACK       uint8 = 0x09 // Selective ACK: confirm blocks and missing packets
)

// StreamDataHeader wraps stream data with a stream ID and length.
// Wire format: [2B stream_id][2B data_len][NB data]
const StreamDataHeaderSize = 4

// EncodeStreamData wraps data with a stream ID and length for multiplexing.
// Multiple entries can be safely concatenated and decoded with DecodeAllStreamData.
func EncodeStreamData(streamID uint16, data []byte) []byte {
	buf := make([]byte, StreamDataHeaderSize+len(data))
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(data)))
	copy(buf[4:], data)
	return buf
}

// DecodeStreamData extracts the first stream ID and data from a payload.
// For payloads with multiple concatenated stream entries, use DecodeAllStreamData.
func DecodeStreamData(payload []byte) (streamID uint16, data []byte, err error) {
	if len(payload) < StreamDataHeaderSize {
		return 0, nil, fmt.Errorf("stream data too short")
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	dataLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if StreamDataHeaderSize+dataLen > len(payload) {
		return 0, nil, fmt.Errorf("stream data length %d exceeds payload size %d", dataLen, len(payload)-StreamDataHeaderSize)
	}
	data = payload[StreamDataHeaderSize : StreamDataHeaderSize+dataLen]
	return streamID, data, nil
}

// StreamEntry represents a single stream data entry in an aggregated packet.
type StreamEntry struct {
	StreamID uint16
	Data     []byte
}

// DecodeAllStreamData decodes all concatenated stream entries from an aggregated payload.
func DecodeAllStreamData(payload []byte) ([]StreamEntry, error) {
	var entries []StreamEntry
	offset := 0
	for offset < len(payload) {
		if offset+StreamDataHeaderSize > len(payload) {
			return nil, fmt.Errorf("truncated stream header at offset %d", offset)
		}
		streamID := binary.BigEndian.Uint16(payload[offset : offset+2])
		dataLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += StreamDataHeaderSize
		if offset+dataLen > len(payload) {
			return nil, fmt.Errorf("stream data length %d exceeds remaining payload at offset %d", dataLen, offset)
		}
		entry := StreamEntry{
			StreamID: streamID,
			Data:     make([]byte, dataLen),
		}
		copy(entry.Data, payload[offset:offset+dataLen])
		entries = append(entries, entry)
		offset += dataLen
	}
	return entries, nil
}

// TunnelHeaderSize is the size of the tunnel packet header.
const TunnelHeaderSize = 11 // 1 flags + 4 session_id + 4 seq_num + 2 data_len

// TunnelPacket represents a tunnel protocol packet carried inside ICMP payload.
//
// Wire format:
//
//	[1B flags][4B session_id][2B seq_num][2B data_len][NB data]
//
// Flags byte:
//
//	bits 0-1: packet type (DATA=0, AUTH=1, CONTROL=2, DIAG=3)
//	bit 2: FRAGMENT flag
//	bit 3: ENCRYPTED flag
//	bit 4: AUTH flag
//	bit 5: SPOOF flag
//	bits 6-7: reserved
type TunnelPacket struct {
	Type      uint8  // Packet type (TypeData, TypeAuth, etc.)
	Flags     uint8  // Additional flags
	SessionID uint32 // Session identifier
	SeqNum    uint32 // Sequence number
	Data      []byte // Payload data

	// In-memory metadata (not encoded)
	ICMPID  uint16
	ICMPSeq uint16
}

// Encode serializes a TunnelPacket into bytes for transmission.
func (p *TunnelPacket) Encode() []byte {
	dataLen := len(p.Data)
	buf := make([]byte, TunnelHeaderSize+dataLen)

	// Flags byte: type in lower 2 bits, other flags OR'd in
	buf[0] = (p.Type & 0x03) | p.Flags

	binary.BigEndian.PutUint32(buf[1:5], p.SessionID)
	binary.BigEndian.PutUint32(buf[5:9], p.SeqNum)
	binary.BigEndian.PutUint16(buf[9:11], uint16(dataLen))

	if dataLen > 0 {
		copy(buf[11:], p.Data)
	}

	return buf
}

// DecodeTunnelPacket deserializes bytes into a TunnelPacket.
func DecodeTunnelPacket(data []byte) (*TunnelPacket, error) {
	if len(data) < TunnelHeaderSize {
		return nil, fmt.Errorf("data too short for tunnel header: %d bytes", len(data))
	}

	flags := data[0]
	dataLen := binary.BigEndian.Uint16(data[9:11])

	if len(data) < TunnelHeaderSize+int(dataLen) {
		return nil, fmt.Errorf("data too short for declared payload: need %d, have %d",
			TunnelHeaderSize+int(dataLen), len(data))
	}

	p := &TunnelPacket{
		Type:      flags & 0x03,
		Flags:     flags & 0xFC, // upper 6 bits
		SessionID: binary.BigEndian.Uint32(data[1:5]),
		SeqNum:    binary.BigEndian.Uint32(data[5:9]),
	}

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		copy(p.Data, data[11:11+dataLen])
	}

	return p, nil
}

// IsEncrypted returns true if the packet has the ENCRYPTED flag.
func (p *TunnelPacket) IsEncrypted() bool {
	return p.Flags&FlagEncrypted != 0
}

// IsFragment returns true if the packet has the FRAGMENT flag.
func (p *TunnelPacket) IsFragment() bool {
	return p.Flags&FlagFragment != 0
}

// IsSpoofed returns true if the packet has the SPOOF flag.
func (p *TunnelPacket) IsSpoofed() bool {
	return p.Flags&FlagSpoof != 0
}
