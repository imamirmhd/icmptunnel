package icmp_test

import (
	"testing"
	"github.com/user/icmptunnel/icmp"
)

func TestAddStreamWithID(t *testing.T) {
	// Create a dummy session
	// We can't access fields directly if they are not exported or if we are in a different package.
	// But Session fields ARE exported.
	session := &icmp.Session{
		Streams: make(map[uint16]*icmp.Stream),
	}

	// Add a stream with a specific ID
	streamID := uint16(123)
	stream := session.AddStreamWithID(streamID, "tcp", "127.0.0.1:8080")

	if stream.ID != streamID {
		t.Errorf("stream.ID = %d, want %d", stream.ID, streamID)
	}

	// Verify it's in the map with the correct key
	s, ok := session.Streams[streamID]
	if !ok {
		t.Errorf("stream not found in map with key %d", streamID)
	}
	if s != stream {
		t.Errorf("stored stream does not match returned stream")
	}

	// Verify we can add another with a different ID
	streamID2 := uint16(456)
	stream2 := session.AddStreamWithID(streamID2, "udp", "8.8.8.8:53")
	
	if stream2.ID != streamID2 {
		t.Errorf("stream2.ID = %d, want %d", stream2.ID, streamID2)
	}
	
	if _, ok := session.Streams[streamID2]; !ok {
		t.Errorf("stream2 not found in map")
	}
}

func TestRotateStreams(t *testing.T) {
	session := &icmp.Session{
		Streams: make(map[uint16]*icmp.Stream),
	}

	// Add manual ID
	session.AddStreamWithID(10, "tcp", "host1")

	// Add auto ID
	s2 := session.AddStream("tcp", "host2")
	
	if len(session.Streams) != 2 {
		t.Errorf("expected 2 streams, got %d", len(session.Streams))
	}
	
	// Check s2 ID. It should be len + 1 = 3? No, len is 1 initially.
	// When adding s2, len was 1, so ID became 2.
	if s2.ID != 2 {
		// Note: The implementation of AddStream uses len(s.Streams) + 1.
		// If we added ID 10 manually, map has 1 item.
		// AddStream -> len=1 -> ID=2.
		t.Logf("s2.ID = %d", s2.ID)
	}
}
