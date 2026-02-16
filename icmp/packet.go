package icmp

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sync"
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
	FlagFragment   uint8 = 1 << 2
	FlagEncrypted  uint8 = 1 << 3
	FlagAuth       uint8 = 1 << 4
	FlagSpoof      uint8 = 1 << 5
	FlagCompressed uint8 = 1 << 6
	FlagCRC        uint8 = 1 << 7 // CRC32 integrity check present
)

// Control subtypes.
const (
	ControlHeartbeat   uint8 = 0x01
	ControlClose       uint8 = 0x02
	ControlAuthOK      uint8 = 0x03
	ControlAuthFail    uint8 = 0x04
	ControlConnect     uint8 = 0x05
	ControlConnectACK  uint8 = 0x06
	ControlConnectFail uint8 = 0x07
	ControlACK         uint8 = 0x08
	ControlSACK        uint8 = 0x09
	ControlResume      uint8 = 0x0A // Session resume request
	ControlResumeACK   uint8 = 0x0B // Session resume acknowledged
	ControlStats       uint8 = 0x0C // Real-time stats report
)

// StreamDataHeader wraps stream data with a stream ID and length.
// Wire format: [2B stream_id][2B data_len][NB data]
const StreamDataHeaderSize = 4

// TunnelHeaderSize is the size of the tunnel packet header.
// [1B flags][4B session_id][4B seq_num][2B data_len] = 11
// With CRC: additional 4 bytes appended after data
const TunnelHeaderSize = 11
const CRCSize = 4

// crc32 table (Castagnoli for hardware acceleration)
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// --- Object Pools ---

var tunnelPacketPool = sync.Pool{
	New: func() interface{} {
		return &TunnelPacket{}
	},
}

// AcquireTunnelPacket gets a TunnelPacket from the pool.
func AcquireTunnelPacket() *TunnelPacket {
	pkt := tunnelPacketPool.Get().(*TunnelPacket)
	pkt.Type = 0
	pkt.Flags = 0
	pkt.SessionID = 0
	pkt.SeqNum = 0
	pkt.Data = pkt.Data[:0]
	pkt.StreamIDs = pkt.StreamIDs[:0]
	pkt.ICMPID = 0
	pkt.ICMPSeq = 0
	pkt.Priority = 0
	return pkt
}

// ReleaseTunnelPacket returns a TunnelPacket to the pool.
func ReleaseTunnelPacket(pkt *TunnelPacket) {
	if pkt == nil {
		return
	}
	tunnelPacketPool.Put(pkt)
}

var encodeBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 2048)
		return &b
	},
}

// EncodeStreamData wraps data with a stream ID and length for multiplexing.
func EncodeStreamData(streamID uint16, data []byte) []byte {
	buf := make([]byte, StreamDataHeaderSize+len(data))
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(data)))
	copy(buf[4:], data)
	return buf
}

// EncodeStreamDataInto encodes stream data into existing buffer, returns bytes written.
func EncodeStreamDataInto(buf []byte, streamID uint16, data []byte) int {
	needed := StreamDataHeaderSize + len(data)
	if len(buf) < needed {
		return 0
	}
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(data)))
	copy(buf[4:], data)
	return needed
}

// DecodeStreamData extracts the first stream ID and data from a payload.
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
// Returns slices into the original payload to avoid copies.
func DecodeAllStreamData(payload []byte) ([]StreamEntry, error) {
	// Pre-estimate capacity to avoid repeated slice growth
	estEntries := len(payload) / 64
	if estEntries < 4 {
		estEntries = 4
	}
	entries := make([]StreamEntry, 0, estEntries)
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
		// Zero-copy: reference into original payload
		entries = append(entries, StreamEntry{
			StreamID: streamID,
			Data:     payload[offset : offset+dataLen],
		})
		offset += dataLen
	}
	return entries, nil
}

// TunnelPacket represents a tunnel protocol packet carried inside ICMP payload.
//
// Wire format:
//
//	[1B flags][4B session_id][4B seq_num][2B data_len][NB data][4B CRC32 (optional)]
//
// Flags byte:
//
//	bits 0-1: packet type (DATA=0, AUTH=1, CONTROL=2, DIAG=3)
//	bit 2: FRAGMENT flag
//	bit 3: ENCRYPTED flag
//	bit 4: AUTH flag
//	bit 5: SPOOF flag
//	bit 6: COMPRESSED flag
//	bit 7: CRC flag
type TunnelPacket struct {
	Type      uint8    // Packet type (TypeData, TypeAuth, etc.)
	Flags     uint8    // Additional flags
	SessionID uint32   // Session identifier
	SeqNum    uint32   // Sequence number
	Data      []byte   // Payload data
	StreamIDs []uint16 // Associated stream IDs (in-memory only)
	Priority  uint8    // 0=normal, 1=control, 2=critical (in-memory only)

	// In-memory metadata (not encoded)
	ICMPID  uint16
	ICMPSeq uint16
}

// Encode serializes a TunnelPacket into bytes for transmission.
func (p *TunnelPacket) Encode() []byte {
	dataLen := len(p.Data)
	crcEnabled := p.Flags&FlagCRC != 0
	totalSize := TunnelHeaderSize + dataLen
	if crcEnabled {
		totalSize += CRCSize
	}
	buf := make([]byte, totalSize)
	p.EncodeInto(buf)
	return buf
}

// EncodeInto serializes a TunnelPacket into a pre-allocated buffer (zero-copy).
// Buffer must be at least TunnelHeaderSize + len(Data) [+ CRCSize if CRC flag] bytes.
// Returns bytes written.
func (p *TunnelPacket) EncodeInto(buf []byte) int {
	dataLen := len(p.Data)
	crcEnabled := p.Flags&FlagCRC != 0

	// Flags byte: type in lower 2 bits, other flags OR'd in
	buf[0] = (p.Type & 0x03) | p.Flags

	binary.BigEndian.PutUint32(buf[1:5], p.SessionID)
	binary.BigEndian.PutUint32(buf[5:9], p.SeqNum)
	binary.BigEndian.PutUint16(buf[9:11], uint16(dataLen))

	if dataLen > 0 {
		copy(buf[11:], p.Data)
	}

	written := TunnelHeaderSize + dataLen

	// Append CRC32 if enabled
	if crcEnabled {
		checksum := crc32.Checksum(buf[:written], crcTable)
		binary.BigEndian.PutUint32(buf[written:written+CRCSize], checksum)
		written += CRCSize
	}

	return written
}

// DecodeTunnelPacket deserializes bytes into a TunnelPacket.
func DecodeTunnelPacket(data []byte) (*TunnelPacket, error) {
	if len(data) < TunnelHeaderSize {
		return nil, fmt.Errorf("data too short for tunnel header: %d bytes", len(data))
	}

	flags := data[0]
	dataLen := binary.BigEndian.Uint16(data[9:11])

	expectedLen := TunnelHeaderSize + int(dataLen)
	crcEnabled := flags&FlagCRC != 0
	if crcEnabled {
		expectedLen += CRCSize
	}

	if len(data) < expectedLen {
		return nil, fmt.Errorf("data too short for declared payload: need %d, have %d",
			expectedLen, len(data))
	}

	// Verify CRC if present
	if crcEnabled {
		payloadEnd := TunnelHeaderSize + int(dataLen)
		storedCRC := binary.BigEndian.Uint32(data[payloadEnd : payloadEnd+CRCSize])
		computedCRC := crc32.Checksum(data[:payloadEnd], crcTable)
		if storedCRC != computedCRC {
			return nil, fmt.Errorf("CRC32 mismatch: stored=%08x computed=%08x (corruption detected)", storedCRC, computedCRC)
		}
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

// HasCRC returns true if the packet has the CRC flag.
func (p *TunnelPacket) HasCRC() bool {
	return p.Flags&FlagCRC != 0
}
