package icmp

import (
	"bytes"
	"testing"
)

// --- TunnelPacket encode/decode ---

func TestEncodeDecodeTunnelPacket(t *testing.T) {
	tests := []struct {
		name string
		pkt  *TunnelPacket
	}{
		{
			name: "data packet",
			pkt: &TunnelPacket{
				Type:      TypeData,
				Flags:     0,
				SessionID: 0xDEADBEEF,
				SeqNum:    42,
				Data:      []byte("hello tunnel"),
			},
		},
		{
			name: "auth packet with flags",
			pkt: &TunnelPacket{
				Type:      TypeAuth,
				Flags:     FlagEncrypted | FlagAuth,
				SessionID: 1,
				SeqNum:    0,
				Data:      []byte("token123"),
			},
		},
		{
			name: "control packet empty payload",
			pkt: &TunnelPacket{
				Type:      TypeControl,
				Flags:     0,
				SessionID: 999,
				SeqNum:    100,
				Data:      nil,
			},
		},
		{
			name: "diag packet with fragment flag",
			pkt: &TunnelPacket{
				Type:      TypeDiag,
				Flags:     FlagFragment,
				SessionID: 0xFFFFFFFF,
				SeqNum:    0xFFFFFFFF,
				Data:      []byte{0x00, 0xFF, 0x80},
			},
		},
		{
			name: "large payload",
			pkt: &TunnelPacket{
				Type:      TypeData,
				SessionID: 5,
				SeqNum:    1,
				Data:      bytes.Repeat([]byte("A"), 1400),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.pkt.Encode()
			decoded, err := DecodeTunnelPacket(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if decoded.Type != tc.pkt.Type {
				t.Errorf("Type: got %d, want %d", decoded.Type, tc.pkt.Type)
			}
			if decoded.Flags != tc.pkt.Flags {
				t.Errorf("Flags: got 0x%02x, want 0x%02x", decoded.Flags, tc.pkt.Flags)
			}
			if decoded.SessionID != tc.pkt.SessionID {
				t.Errorf("SessionID: got %d, want %d", decoded.SessionID, tc.pkt.SessionID)
			}
			if decoded.SeqNum != tc.pkt.SeqNum {
				t.Errorf("SeqNum: got %d, want %d", decoded.SeqNum, tc.pkt.SeqNum)
			}
			if !bytes.Equal(decoded.Data, tc.pkt.Data) {
				t.Errorf("Data mismatch: got %d bytes, want %d bytes", len(decoded.Data), len(tc.pkt.Data))
			}
		})
	}
}

func TestDecodeTruncatedPacket(t *testing.T) {
	// Too short for header
	_, err := DecodeTunnelPacket([]byte{0x00, 0x01})
	if err == nil {
		t.Error("Expected error for truncated header, got nil")
	}

	// Header claims more data than available
	pkt := &TunnelPacket{
		Type:      TypeData,
		SessionID: 1,
		SeqNum:    1,
		Data:      []byte("hello"),
	}
	encoded := pkt.Encode()
	// Truncate the payload
	truncated := encoded[:TunnelHeaderSize+2]
	_, err = DecodeTunnelPacket(truncated)
	if err == nil {
		t.Error("Expected error for truncated payload, got nil")
	}
}

func TestDecodeEmptyData(t *testing.T) {
	// Exactly TunnelHeaderSize, no payload
	pkt := &TunnelPacket{
		Type:      TypeControl,
		SessionID: 42,
		SeqNum:    0,
		Data:      nil,
	}
	encoded := pkt.Encode()
	if len(encoded) != TunnelHeaderSize {
		t.Fatalf("Expected %d bytes for empty packet, got %d", TunnelHeaderSize, len(encoded))
	}

	decoded, err := DecodeTunnelPacket(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if len(decoded.Data) != 0 {
		t.Errorf("Expected empty data, got %d bytes", len(decoded.Data))
	}
}

// --- Flag methods ---

func TestFlagMethods(t *testing.T) {
	pkt := &TunnelPacket{Flags: FlagEncrypted | FlagFragment | FlagSpoof}

	if !pkt.IsEncrypted() {
		t.Error("IsEncrypted should be true")
	}
	if !pkt.IsFragment() {
		t.Error("IsFragment should be true")
	}
	if !pkt.IsSpoofed() {
		t.Error("IsSpoofed should be true")
	}

	pkt2 := &TunnelPacket{Flags: 0}
	if pkt2.IsEncrypted() {
		t.Error("IsEncrypted should be false")
	}
	if pkt2.IsFragment() {
		t.Error("IsFragment should be false")
	}
	if pkt2.IsSpoofed() {
		t.Error("IsSpoofed should be false")
	}
}

// --- Stream data encoding/decoding ---

func TestEncodeDecodeStreamData(t *testing.T) {
	streamID := uint16(42)
	data := []byte("stream payload")

	encoded := EncodeStreamData(streamID, data)
	decodedID, decodedData, err := DecodeStreamData(encoded)
	if err != nil {
		t.Fatalf("DecodeStreamData failed: %v", err)
	}
	if decodedID != streamID {
		t.Errorf("StreamID: got %d, want %d", decodedID, streamID)
	}
	if !bytes.Equal(decodedData, data) {
		t.Errorf("Data mismatch")
	}
}

func TestDecodeStreamDataTooShort(t *testing.T) {
	_, _, err := DecodeStreamData([]byte{0x00})
	if err == nil {
		t.Error("Expected error for short stream data")
	}
}

func TestDecodeAllStreamData(t *testing.T) {
	// Concatenate 3 stream entries
	var combined []byte
	entries := []struct {
		id   uint16
		data []byte
	}{
		{1, []byte("first")},
		{2, []byte("second")},
		{3, []byte("third")},
	}

	for _, e := range entries {
		combined = append(combined, EncodeStreamData(e.id, e.data)...)
	}

	decoded, err := DecodeAllStreamData(combined)
	if err != nil {
		t.Fatalf("DecodeAllStreamData failed: %v", err)
	}

	if len(decoded) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(decoded))
	}

	for i, e := range entries {
		if decoded[i].StreamID != e.id {
			t.Errorf("Entry %d StreamID: got %d, want %d", i, decoded[i].StreamID, e.id)
		}
		if !bytes.Equal(decoded[i].Data, e.data) {
			t.Errorf("Entry %d Data mismatch", i)
		}
	}
}

func TestDecodeAllStreamDataTruncated(t *testing.T) {
	data := EncodeStreamData(1, []byte("hello"))
	// Truncate mid-payload
	_, err := DecodeAllStreamData(data[:len(data)-2])
	if err == nil {
		t.Error("Expected error for truncated stream data")
	}
}

func TestDecodeStreamDataEmptyPayload(t *testing.T) {
	encoded := EncodeStreamData(99, []byte{})
	id, data, err := DecodeStreamData(encoded)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if id != 99 {
		t.Errorf("StreamID: got %d, want 99", id)
	}
	if len(data) != 0 {
		t.Errorf("Expected empty data, got %d bytes", len(data))
	}
}

// --- Control message encoding ---

func TestEncodeDecodeControlMessage(t *testing.T) {
	subtypes := []uint8{ControlHeartbeat, ControlClose, ControlACK, ControlSACK, ControlConnect}
	for _, st := range subtypes {
		encoded := EncodeControlMessage(st, 12345)
		decodedST, decodedVal, err := DecodeControlMessage(encoded)
		if err != nil {
			t.Fatalf("DecodeControlMessage failed for subtype %d: %v", st, err)
		}
		if decodedST != st {
			t.Errorf("Subtype: got %d, want %d", decodedST, st)
		}
		if decodedVal != 12345 {
			t.Errorf("Value: got %d, want 12345", decodedVal)
		}
	}
}

func TestDecodeControlMessageTooShort(t *testing.T) {
	_, _, err := DecodeControlMessage([]byte{})
	if err == nil {
		t.Error("Expected error for empty control message")
	}
}

// --- ConnectRequest encoding ---

func TestEncodeDecodeConnectRequest(t *testing.T) {
	req := &ConnectRequest{
		StreamID:    100,
		Protocol:    "tcp",
		Destination: "10.0.0.1:8080",
	}

	encoded := EncodeConnectRequest(req)
	decoded, err := DecodeConnectRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeConnectRequest failed: %v", err)
	}

	if decoded.StreamID != req.StreamID {
		t.Errorf("StreamID: got %d, want %d", decoded.StreamID, req.StreamID)
	}
	if decoded.Protocol != req.Protocol {
		t.Errorf("Protocol: got %q, want %q", decoded.Protocol, req.Protocol)
	}
	if decoded.Destination != req.Destination {
		t.Errorf("Destination: got %q, want %q", decoded.Destination, req.Destination)
	}
}
