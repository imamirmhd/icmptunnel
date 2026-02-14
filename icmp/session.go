package icmp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
	"bytes"
	"compress/flate"
	"io"
	"sort"

	"github.com/user/icmptunnel/logger"
)

// Session tracks state for a single tunnel connection.
type Session struct {
	ID            uint32
	ClientAddr    net.IP
	NextSeqSend   uint16
	NextSeqRecv   uint16
	Authenticated bool
	AuthToken     string
	CreatedAt     time.Time
	LastActivity  time.Time
	Streams       map[uint16]*Stream // Multiplexed streams within a session
	recvBuf       map[uint16]*TunnelPacket
	nextRecvSeq   uint16
	
	// Sliding Window & Congestion Control
	mu            sync.Mutex
	inflight      map[uint16]*inflightPacket
	cwnd          int
	ssthresh      int
	srtt          time.Duration
	rttvar        time.Duration
	rto           time.Duration

	// SACK state
	receivedSeqs  map[uint16]bool
}

type inflightPacket struct {
	Pkt      *TunnelPacket
	SentAt   time.Time
	Retries  int
}

type SACK struct {
	AckedSeq uint16   // Highest in-order sequence received
	Blocks   []uint16 // Ranges of out-of-order blocks: [start1, end1, start2, end2, ...]
}

// Stream represents a single TCP/UDP forwarding stream within a session.
type Stream struct {
	ID          uint16
	Protocol    string // "tcp" or "udp"
	Destination string // host:port
	DataChan    chan []byte
	Done        chan struct{}
	CreatedAt   time.Time
}

// SessionManager manages multiple tunnel sessions.
type SessionManager struct {
	sessions       map[uint32]*Session
	sessionsByAddr map[string]*Session // keyed by client IP string
	mu             sync.RWMutex
	log            *logger.Logger
	timeout        time.Duration
}

// NewSessionManager creates a new session manager.
func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions:       make(map[uint32]*Session),
		sessionsByAddr: make(map[string]*Session),
		log:            logger.Default().WithComponent("session-mgr"),
		timeout:        timeout,
	}
	go sm.cleanupLoop()
	return sm
}

// CreateSessionWithID creates a new session with a specific ID.
func (sm *SessionManager) CreateSessionWithID(clientAddr net.IP, id uint32) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()

	session := &Session{
		ID:           id,
		ClientAddr:   clientAddr,
		CreatedAt:     now,
		LastActivity:  now,
		Streams:       make(map[uint16]*Stream),
		recvBuf:       make(map[uint16]*TunnelPacket),
		nextRecvSeq:   0,
		inflight:      make(map[uint16]*inflightPacket),
		cwnd:          10, // Initial window size
		ssthresh:      64,
		rto:           time.Second,
		receivedSeqs:  make(map[uint16]bool),
	}

	sm.sessions[id] = session
	sm.sessionsByAddr[clientAddr.String()] = session
	sm.log.Info("Created session %08x for client %s", id, clientAddr)
	return session
}

// CreateSession creates a new session for the given client.
func (sm *SessionManager) CreateSession(clientAddr net.IP) *Session {
	id := generateSessionID()
	return sm.CreateSessionWithID(clientAddr, id)
}

// GetSession returns a session by its ID.
func (sm *SessionManager) GetSession(id uint32) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// GetSessionByAddr returns a session by the client's address.
func (sm *SessionManager) GetSessionByAddr(addr net.IP) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionsByAddr[addr.String()]
}

// RemoveSession removes a session by its ID.
func (sm *SessionManager) RemoveSession(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, ok := sm.sessions[id]; ok {
		delete(sm.sessionsByAddr, session.ClientAddr.String())
		delete(sm.sessions, id)
		sm.log.Info("Removed session %08x", id)
	}
}

// TouchSession updates the last activity timestamp for a session.
func (sm *SessionManager) TouchSession(id uint32) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if session, ok := sm.sessions[id]; ok {
		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()
	}
}

// GetNextSeq returns and increments the send sequence number.
func (s *Session) GetNextSeq() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.NextSeqSend
	s.NextSeqSend++
	return seq
}

// RecordSent records a packet as being in-flight.
func (s *Session) RecordSent(pkt *TunnelPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight[pkt.SeqNum] = &inflightPacket{
		Pkt:    pkt,
		SentAt: time.Now(),
	}
}

// ProcessACK handles an incoming ACK or SACK.
// Returns a list of newly acknowledged packets.
func (s *Session) ProcessACK(ackedSeq uint16, sackBlocks []uint16) []*TunnelPacket {
	s.mu.Lock()
	defer s.mu.Unlock()

	var acknowledged []*TunnelPacket

	// Simple cumulative ACK
	for seq, inflight := range s.inflight {
		// seq <= ackedSeq (considering wraparound)
		if (seq <= ackedSeq && ackedSeq - seq < 32768) || (seq > ackedSeq && seq - ackedSeq > 32768) {
			acknowledged = append(acknowledged, inflight.Pkt)
			s.UpdateRTT(time.Since(inflight.SentAt))
			delete(s.inflight, seq)
		}
	}

	// SACK blocks
	for i := 0; i+1 < len(sackBlocks); i += 2 {
		start := sackBlocks[i]
		end := sackBlocks[i+1]
		for seq := start; ; {
			if inflight, ok := s.inflight[seq]; ok {
				acknowledged = append(acknowledged, inflight.Pkt)
				s.UpdateRTT(time.Since(inflight.SentAt))
				delete(s.inflight, seq)
			}
			if seq == end {
				break
			}
			seq++
		}
	}

	// Update congestion window
	if len(acknowledged) > 0 {
		if s.cwnd < s.ssthresh {
			s.cwnd += len(acknowledged) // Slow start
		} else {
			s.cwnd += 1 // Congestion avoidance
		}
	}

	return acknowledged
}

func (s *Session) UpdateRTT(measured time.Duration) {
	if s.srtt == 0 {
		s.srtt = measured
		s.rttvar = measured / 2
	} else {
		delta := measured - s.srtt
		if delta < 0 {
			delta = -delta
		}
		s.rttvar = time.Duration(0.75*float64(s.rttvar) + 0.25*float64(delta))
		s.srtt = time.Duration(0.875*float64(s.srtt) + 0.125*float64(measured))
	}
	s.rto = s.srtt + 4*s.rttvar
	if s.rto < 200*time.Millisecond {
		s.rto = 200 * time.Millisecond
	}
}

// GetRetransmissions returns packets that have timed out.
func (s *Session) GetRetransmissions() []*TunnelPacket {
	s.mu.Lock()
	defer s.mu.Unlock()

	var retrans []*TunnelPacket
	now := time.Now()
	for _, inflight := range s.inflight {
		if now.Sub(inflight.SentAt) > s.rto {
			inflight.SentAt = now
			inflight.Retries++
			retrans = append(retrans, inflight.Pkt)
		}
	}

	if len(retrans) > 0 {
		// Congestion: back off
		s.ssthresh = s.cwnd / 2
		if s.ssthresh < 2 {
			s.ssthresh = 2
		}
		s.cwnd = 1
	}

	return retrans
}

// GenerateSACK creates a SACK message based on received packets.
func (s *Session) GenerateSACK() *SACK {
	s.mu.Lock()
	defer s.mu.Unlock()

	sack := &SACK{
		AckedSeq: s.nextRecvSeq - 1,
	}

	var keys []int
	for seq := range s.receivedSeqs {
		if seq >= s.nextRecvSeq {
			keys = append(keys, int(seq))
		}
	}
	if len(keys) == 0 {
		return sack
	}
	
	// Sort keys
	sort.Ints(keys)

	start := uint16(keys[0])
	end := uint16(keys[0])
	for i := 1; i < len(keys); i++ {
		if keys[i] == int(end)+1 {
			end = uint16(keys[i])
		} else {
			sack.Blocks = append(sack.Blocks, start, end)
			start = uint16(keys[i])
			end = uint16(keys[i])
			if len(sack.Blocks) >= 8 {
				break
			}
		}
	}
	if len(sack.Blocks) < 8 {
		sack.Blocks = append(sack.Blocks, start, end)
	}

	return sack
}

// MarkReceived records a sequence number as received.
func (s *Session) MarkReceived(seq uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receivedSeqs[seq] = true
	// Clean up old received seqs?
	if len(s.receivedSeqs) > 2000 {
		for k := range s.receivedSeqs {
			if k < s.nextRecvSeq-500 {
				delete(s.receivedSeqs, k)
			}
		}
	}
}

// ProcessIncoming handles sequence numbers and reordering.
// Returns a slice of packets that are now in-order and ready to be processed.
func (s *Session) ProcessIncoming(pkt *TunnelPacket) []*TunnelPacket {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.receivedSeqs[pkt.SeqNum] = true

	// If this is exactly what we expect
	if pkt.SeqNum == s.nextRecvSeq {
		s.nextRecvSeq++
		result := []*TunnelPacket{pkt}

		// Check buffer for subsequent packets
		for {
			if nextPkt, ok := s.recvBuf[s.nextRecvSeq]; ok {
				result = append(result, nextPkt)
				delete(s.recvBuf, s.nextRecvSeq)
				s.nextRecvSeq++
			} else {
				break
			}
		}
		return result
	}

	// Out of order: buffer it if it's not too far ahead
	diff := pkt.SeqNum - s.nextRecvSeq
	if diff < 1000 { // Max 1000 packets ahead
		s.recvBuf[pkt.SeqNum] = pkt
	}
	
	return nil
}

// Compress applies flate compression to data.
func (s *Session) Compress(data []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestSpeed)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// Decompress removes flate compression from data.
func (s *Session) Decompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

// AddStream adds a new data stream to the session.
func (s *Session) AddStream(protocol, destination string) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uint16(len(s.Streams) + 1)
	stream := &Stream{
		ID:          id,
		Protocol:    protocol,
		Destination: destination,
		DataChan:    make(chan []byte, 256),
		Done:        make(chan struct{}),
		CreatedAt:   time.Now(),
	}
	s.Streams[id] = stream
	return stream
}

// RemoveStream removes a stream from the session.
func (s *Session) RemoveStream(id uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if stream, ok := s.Streams[id]; ok {
		close(stream.Done)
		delete(s.Streams, id)
	}
}

// Iterate calls f for each active session.
func (sm *SessionManager) Iterate(f func(*Session)) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, s := range sm.sessions {
		f(s)
	}
}

// cleanupLoop periodically removes timed-out sessions.
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			session.mu.Lock()
			if now.Sub(session.LastActivity) > sm.timeout {
				sm.log.Info("Session %08x timed out (idle %v)", id, now.Sub(session.LastActivity))
				delete(sm.sessionsByAddr, session.ClientAddr.String())
				delete(sm.sessions, id)
			}
			session.mu.Unlock()
		}
		sm.mu.Unlock()
	}
}

// ActiveSessions returns the number of active sessions.
func (sm *SessionManager) ActiveSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

func generateSessionID() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return binary.BigEndian.Uint32(b)
}

// GenerateStreamID creates a random stream ID.
func GenerateStreamID() uint16 {
	n, _ := rand.Int(rand.Reader, big.NewInt(65535))
	return uint16(n.Int64()) + 1
}

// ConnectRequest is embedded in a CONTROL/ControlConnect packet.
// Wire format: [2B stream_id][1B proto_len][NB proto][2B dest_len][NB dest]
type ConnectRequest struct {
	StreamID    uint16
	Protocol    string
	Destination string
}

// EncodeConnectRequest serializes a connect request.
func EncodeConnectRequest(req *ConnectRequest) []byte {
	protoBytes := []byte(req.Protocol)
	destBytes := []byte(req.Destination)
	// Format: [1B subtype][2B stream_id][1B proto_len][NB proto][2B dest_len][NB dest]
	buf := make([]byte, 1+2+1+len(protoBytes)+2+len(destBytes))

	buf[0] = ControlConnect
	binary.BigEndian.PutUint16(buf[1:3], req.StreamID)
	buf[3] = byte(len(protoBytes))
	copy(buf[4:4+len(protoBytes)], protoBytes)
	off := 4 + len(protoBytes)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(destBytes)))
	copy(buf[off+2:], destBytes)

	return buf
}

// DecodeConnectRequest deserializes a connect request (payload after subtype).
func DecodeConnectRequest(data []byte) (*ConnectRequest, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("connect request too short")
	}

	if data[0] != ControlConnect {
		return nil, fmt.Errorf("not a connect request: %02x", data[0])
	}

	req := &ConnectRequest{}
	req.StreamID = binary.BigEndian.Uint16(data[1:3])
	protoLen := int(data[3])
	if len(data) < 4+protoLen+2 {
		return nil, fmt.Errorf("connect request truncated at protocol")
	}
	req.Protocol = string(data[4 : 4+protoLen])
	off := 4 + protoLen
	destLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	if len(data) < off+2+destLen {
		return nil, fmt.Errorf("connect request truncated at destination")
	}
	req.Destination = string(data[off+2 : off+2+destLen])

	return req, nil
}

// EncodeControlMessage creates a simple control message with subtype and optional stream ID.
func EncodeControlMessage(subtype uint8, streamID uint16) []byte {
	buf := make([]byte, 3)
	buf[0] = subtype
	binary.BigEndian.PutUint16(buf[1:3], streamID)
	return buf
}

// DecodeControlMessage extracts subtype and streamID from a control packet.
func DecodeControlMessage(data []byte) (subtype uint8, streamID uint16, err error) {
	if len(data) < 1 {
		return 0, 0, fmt.Errorf("control message too short")
	}
	subtype = data[0]
	if len(data) >= 3 {
		streamID = binary.BigEndian.Uint16(data[1:3])
	}
	return subtype, streamID, nil
}
// EncodeSACK serializes a SACK message.
func EncodeSACK(s *SACK) []byte {
	buf := make([]byte, 3 + len(s.Blocks)*2)
	buf[0] = ControlSACK
	binary.BigEndian.PutUint16(buf[1:3], s.AckedSeq)
	for i, b := range s.Blocks {
		binary.BigEndian.PutUint16(buf[3+i*2:5+i*2], b)
	}
	return buf
}

// DecodeSACK deserializes a SACK message.
func DecodeSACK(data []byte) (*SACK, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("SACK too short")
	}
	s := &SACK{
		AckedSeq: binary.BigEndian.Uint16(data[1:3]),
	}
	for i := 3; i+1 < len(data); i += 2 {
		s.Blocks = append(s.Blocks, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return s, nil
}
