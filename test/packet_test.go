package icmp_test

import (
	"testing"

	"github.com/user/icmptunnel/icmp"
)

// TestStreamDataEncoding tests single stream entry encoding and decoding.
func TestStreamDataEncoding(t *testing.T) {
	originalData := []byte("hello world test data")
	var streamID uint16 = 42

	encoded := icmp.EncodeStreamData(streamID, originalData)

	// Verify the encoded format: [2B streamID][2B dataLen][data]
	if len(encoded) != 4+len(originalData) {
		t.Fatalf("encoded length = %d, want %d", len(encoded), 4+len(originalData))
	}

	decodedID, decodedData, err := icmp.DecodeStreamData(encoded)
	if err != nil {
		t.Fatalf("DecodeStreamData error: %v", err)
	}
	if decodedID != streamID {
		t.Errorf("decoded streamID = %d, want %d", decodedID, streamID)
	}
	if string(decodedData) != string(originalData) {
		t.Errorf("decoded data = %q, want %q", decodedData, originalData)
	}
}

// TestMultiStreamAggregation tests encoding multiple stream entries and decoding
// them all correctly. This was the critical bug: without length delimiters,
// aggregated multi-stream data could not be decoded.
func TestMultiStreamAggregation(t *testing.T) {
	entries := []struct {
		streamID uint16
		data     []byte
	}{
		{1, []byte("stream one data")},
		{2, []byte("stream two data here")},
		{3, []byte("third stream")},
	}

	// Aggregate entries (this is what client.handleData does)
	var aggregated []byte
	for _, e := range entries {
		aggregated = append(aggregated, icmp.EncodeStreamData(e.streamID, e.data)...)
	}

	// Decode all entries (this is what server.handleData should do)
	decoded, err := icmp.DecodeAllStreamData(aggregated)
	if err != nil {
		t.Fatalf("DecodeAllStreamData error: %v", err)
	}

	if len(decoded) != len(entries) {
		t.Fatalf("decoded %d entries, want %d", len(decoded), len(entries))
	}

	for i, entry := range decoded {
		if entry.StreamID != entries[i].streamID {
			t.Errorf("entry[%d] streamID = %d, want %d", i, entry.StreamID, entries[i].streamID)
		}
		if string(entry.Data) != string(entries[i].data) {
			t.Errorf("entry[%d] data = %q, want %q", i, entry.Data, entries[i].data)
		}
	}
}

// TestMultiStreamSingleEntry verifies that a single aggregated entry decodes fine.
func TestMultiStreamSingleEntry(t *testing.T) {
	data := []byte("single stream test")
	encoded := icmp.EncodeStreamData(7, data)

	decoded, err := icmp.DecodeAllStreamData(encoded)
	if err != nil {
		t.Fatalf("DecodeAllStreamData error: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded %d entries, want 1", len(decoded))
	}
	if decoded[0].StreamID != 7 {
		t.Errorf("streamID = %d, want 7", decoded[0].StreamID)
	}
	if string(decoded[0].Data) != string(data) {
		t.Errorf("data = %q, want %q", decoded[0].Data, data)
	}
}

// TestStreamDataTruncated tests error handling for truncated payloads.
func TestStreamDataTruncated(t *testing.T) {
	// Too short for header
	_, _, err := icmp.DecodeStreamData([]byte{0x00})
	if err == nil {
		t.Error("expected error for truncated header")
	}

	// Header says more data than available
	bad := []byte{0x00, 0x01, 0x00, 0xFF} // streamID=1, dataLen=255, but no data follows
	_, _, err = icmp.DecodeStreamData(bad)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

// TestTunnelPacketEncodeDecode tests full tunnel packet round-trip.
func TestTunnelPacketEncodeDecode(t *testing.T) {
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeAuth,
		Flags:     icmp.FlagAuth,
		SessionID: 0xDEADBEEF,
		SeqNum:    42,
		Data:      []byte("test-token-12345"),
	}

	encoded := pkt.Encode()
	decoded, err := icmp.DecodeTunnelPacket(encoded)
	if err != nil {
		t.Fatalf("DecodeTunnelPacket error: %v", err)
	}

	if decoded.Type != pkt.Type {
		t.Errorf("Type = %d, want %d", decoded.Type, pkt.Type)
	}
	if decoded.SessionID != pkt.SessionID {
		t.Errorf("SessionID = %08x, want %08x", decoded.SessionID, pkt.SessionID)
	}
	if decoded.SeqNum != pkt.SeqNum {
		t.Errorf("SeqNum = %d, want %d", decoded.SeqNum, pkt.SeqNum)
	}
	if string(decoded.Data) != string(pkt.Data) {
		t.Errorf("Data = %q, want %q", decoded.Data, pkt.Data)
	}
}

// TestEmptyStreamData tests encoding/decoding of zero-length data.
func TestEmptyStreamData(t *testing.T) {
	encoded := icmp.EncodeStreamData(99, []byte{})
	decoded, err := icmp.DecodeAllStreamData(encoded)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded %d entries, want 1", len(decoded))
	}
	if decoded[0].StreamID != 99 {
		t.Errorf("streamID = %d, want 99", decoded[0].StreamID)
	}
	if len(decoded[0].Data) != 0 {
		t.Errorf("data length = %d, want 0", len(decoded[0].Data))
	}
}

// TestLargeMultiStreamAggregation tests with many streams and large data.
func TestLargeMultiStreamAggregation(t *testing.T) {
	var aggregated []byte
	numStreams := 50
	dataSize := 100

	for i := 0; i < numStreams; i++ {
		data := make([]byte, dataSize)
		for j := range data {
			data[j] = byte(i)
		}
		aggregated = append(aggregated, icmp.EncodeStreamData(uint16(i), data)...)
	}

	decoded, err := icmp.DecodeAllStreamData(aggregated)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(decoded) != numStreams {
		t.Fatalf("decoded %d entries, want %d", len(decoded), numStreams)
	}

	for i, entry := range decoded {
		if entry.StreamID != uint16(i) {
			t.Errorf("entry[%d] streamID = %d, want %d", i, entry.StreamID, i)
		}
		if len(entry.Data) != dataSize {
			t.Errorf("entry[%d] data length = %d, want %d", i, len(entry.Data), dataSize)
		}
		for j, b := range entry.Data {
			if b != byte(i) {
				t.Errorf("entry[%d] data[%d] = %d, want %d", i, j, b, byte(i))
				break
			}
		}
	}
}
