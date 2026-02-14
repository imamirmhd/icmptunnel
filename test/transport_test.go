package icmp_test

import (
	"net"
	"testing"
	"time"

	"github.com/user/icmptunnel/icmp"
)

// createTestSession creates a session via SessionManager for testing.
func createTestSession() *icmp.Session {
	sm := icmp.NewSessionManager(5 * time.Minute)
	return sm.CreateSession(net.ParseIP("127.0.0.1"))
}

// TestSACKEncodeDecode verifies SACK packet encoding and decoding round-trip.
func TestSACKEncodeDecode(t *testing.T) {
	original := &icmp.SACK{
		AckedSeq: 42,
		Blocks:   []uint16{45, 47, 50, 50, 55, 60},
	}

	encoded := icmp.EncodeSACK(original)
	decoded, err := icmp.DecodeSACK(encoded)
	if err != nil {
		t.Fatalf("DecodeSACK error: %v", err)
	}

	if decoded.AckedSeq != original.AckedSeq {
		t.Errorf("AckedSeq = %d, want %d", decoded.AckedSeq, original.AckedSeq)
	}

	if len(decoded.Blocks) != len(original.Blocks) {
		t.Fatalf("Blocks count = %d, want %d", len(decoded.Blocks), len(original.Blocks))
	}

	for i, b := range decoded.Blocks {
		if b != original.Blocks[i] {
			t.Errorf("Block[%d] = %d, want %d", i, b, original.Blocks[i])
		}
	}
}

// TestSACKEncodePacket verifies a SACK can be wrapped into a TunnelPacket.
func TestSACKEncodePacket(t *testing.T) {
	sack := &icmp.SACK{
		AckedSeq: 100,
		Blocks:   []uint16{105, 107},
	}

	pkt := sack.EncodePacket(0xDEADBEEF)

	if pkt.Type != icmp.TypeControl {
		t.Errorf("Type = %d, want %d", pkt.Type, icmp.TypeControl)
	}
	if pkt.SessionID != 0xDEADBEEF {
		t.Errorf("SessionID = %08x, want DEADBEEF", pkt.SessionID)
	}
	if pkt.SeqNum != 0 {
		t.Errorf("SeqNum = %d, want 0 (SACKs aren't sequenced)", pkt.SeqNum)
	}

	// Decode it back
	decoded, err := icmp.DecodeSACK(pkt.Data)
	if err != nil {
		t.Fatalf("DecodeSACK from packet error: %v", err)
	}
	if decoded.AckedSeq != 100 {
		t.Errorf("decoded AckedSeq = %d, want 100", decoded.AckedSeq)
	}
}

// TestSACKEmptyBlocks verifies SACK with no out-of-order blocks.
func TestSACKEmptyBlocks(t *testing.T) {
	original := &icmp.SACK{
		AckedSeq: 7,
		Blocks:   nil,
	}

	encoded := icmp.EncodeSACK(original)
	decoded, err := icmp.DecodeSACK(encoded)
	if err != nil {
		t.Fatalf("DecodeSACK error: %v", err)
	}

	if decoded.AckedSeq != 7 {
		t.Errorf("AckedSeq = %d, want 7", decoded.AckedSeq)
	}
	if len(decoded.Blocks) != 0 {
		t.Errorf("Blocks = %v, want empty", decoded.Blocks)
	}
}

// TestSACKTooShort verifies DecodeSACK returns error for truncated data.
func TestSACKTooShort(t *testing.T) {
	_, err := icmp.DecodeSACK([]byte{0x09, 0x00})
	if err == nil {
		t.Error("expected error for truncated SACK")
	}
}

// TestControlMessageEncodeDecode tests control message round-trip.
func TestControlMessageEncodeDecode(t *testing.T) {
	testCases := []struct {
		subtype  uint8
		streamID uint16
	}{
		{icmp.ControlConnect, 12345},
		{icmp.ControlClose, 0},
		{icmp.ControlHeartbeat, 0},
		{icmp.ControlACK, 42},
		{icmp.ControlConnectACK, 12345},
		{icmp.ControlConnectFail, 12345},
	}

	for _, tc := range testCases {
		encoded := icmp.EncodeControlMessage(tc.subtype, tc.streamID)
		subtype, streamID, err := icmp.DecodeControlMessage(encoded)
		if err != nil {
			t.Errorf("subtype=%d: decode error: %v", tc.subtype, err)
			continue
		}
		if subtype != tc.subtype {
			t.Errorf("subtype = %d, want %d", subtype, tc.subtype)
		}
		if streamID != tc.streamID {
			t.Errorf("streamID = %d, want %d", streamID, tc.streamID)
		}
	}
}

// TestMaxStreamDataSizeConstants verifies that the header size constants
// are correct, ensuring the client and server calculate the same max stream data.
func TestMaxStreamDataSizeConstants(t *testing.T) {
	maxPacketSize := 1472

	// Base calculation: maxPacketSize - 8 (ICMP header) - TunnelHeaderSize - StreamDataHeaderSize
	room := maxPacketSize - 8 - icmp.TunnelHeaderSize - icmp.StreamDataHeaderSize

	expectedRoom := 1472 - 8 - 9 - 4 // = 1451
	if room != expectedRoom {
		t.Errorf("max stream data size = %d, want %d", room, expectedRoom)
	}

	// Verify the constant values match the packet format
	if icmp.TunnelHeaderSize != 9 {
		t.Errorf("TunnelHeaderSize = %d, want 9 (1B type+flags + 4B sessionID + 2B seqNum + 2B reserved)", icmp.TunnelHeaderSize)
	}
	if icmp.StreamDataHeaderSize != 4 {
		t.Errorf("StreamDataHeaderSize = %d, want 4 (2B streamID + 2B dataLen)", icmp.StreamDataHeaderSize)
	}
}

// TestProcessACKCumulativeAndSACK verifies ProcessACK works correctly
// using sessions created through the SessionManager.
func TestProcessACKCumulativeAndSACK(t *testing.T) {
	session := createTestSession()

	// Record 5 sent packets with seq 1-5
	for seq := uint16(1); seq <= 5; seq++ {
		session.RecordSent(&icmp.TunnelPacket{SeqNum: seq})
	}

	// ACK cumulative=3, no SACK blocks - should clear 1,2,3
	acked := session.ProcessACK(3, nil)
	if len(acked) != 3 {
		t.Errorf("expected 3 acked packets after ACK(3), got %d", len(acked))
	}

	// ACK cumulative=5 - should clear remaining 4,5
	acked = session.ProcessACK(5, nil)
	if len(acked) != 2 {
		t.Errorf("expected 2 acked packets after ACK(5), got %d", len(acked))
	}

	// No more packets to ACK
	acked = session.ProcessACK(5, nil)
	if len(acked) != 0 {
		t.Errorf("expected 0 acked packets (nothing in flight), got %d", len(acked))
	}
}

// TestProcessACKWithSACKBlocks verifies ProcessACK with selective ack blocks.
func TestProcessACKWithSACKBlocks(t *testing.T) {
	session := createTestSession()

	// Record packets 1-10
	for seq := uint16(1); seq <= 10; seq++ {
		session.RecordSent(&icmp.TunnelPacket{SeqNum: seq})
	}

	// ACK cumulative=3 with SACK blocks [6,7] and [9,9]
	// Should acknowledge: 1,2,3 (cumulative) + 6,7 (SACK) + 9 (SACK) = 6 total
	sackBlocks := []uint16{6, 7, 9, 9}
	acked := session.ProcessACK(3, sackBlocks)
	if len(acked) != 6 {
		t.Errorf("expected 6 acked, got %d", len(acked))
	}

	// ACK remaining (4,5,8,10)
	acked = session.ProcessACK(10, nil)
	if len(acked) != 4 {
		t.Errorf("expected 4 remaining acked, got %d", len(acked))
	}
}

// TestProcessIncomingOrdering tests that ProcessIncoming correctly orders packets.
func TestProcessIncomingOrdering(t *testing.T) {
	session := createTestSession()
	session.NextRecvSeq = 1

	// Receive packet 1 - should be delivered immediately
	delivered := session.ProcessIncoming(&icmp.TunnelPacket{SeqNum: 1, Type: icmp.TypeData, Data: []byte("pkt1")})
	if len(delivered) != 1 {
		t.Fatalf("expected 1 delivered after seq=1, got %d", len(delivered))
	}

	// Receive packet 3 out of order - should be buffered
	delivered = session.ProcessIncoming(&icmp.TunnelPacket{SeqNum: 3, Type: icmp.TypeData, Data: []byte("pkt3")})
	if len(delivered) != 0 {
		t.Errorf("expected 0 delivered after seq=3 (out of order), got %d", len(delivered))
	}

	// Receive packet 2 - should deliver both 2 and 3
	delivered = session.ProcessIncoming(&icmp.TunnelPacket{SeqNum: 2, Type: icmp.TypeData, Data: []byte("pkt2")})
	if len(delivered) != 2 {
		t.Errorf("expected 2 delivered after seq=2 (fills gap), got %d", len(delivered))
	}
}

// TestGenerateSACK tests that GenerateSACK generates correct SACK info.
func TestGenerateSACK(t *testing.T) {
	session := createTestSession()
	session.NextRecvSeq = 1

	// Receive packets 1, 2, 3 in order
	for seq := uint16(1); seq <= 3; seq++ {
		session.ProcessIncoming(&icmp.TunnelPacket{SeqNum: seq, Type: icmp.TypeData, Data: []byte("data")})
	}

	sack := session.GenerateSACK()
	if sack.AckedSeq != 3 {
		t.Errorf("AckedSeq = %d, want 3 (after receiving 1,2,3)", sack.AckedSeq)
	}
}
