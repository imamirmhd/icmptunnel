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
	"compress/zlib"
	"io"
	"sort"
	"context"

	"github.com/user/icmptunnel/logger"
)

// Session tracks state for a single tunnel connection.
type Session struct {
	ID            uint32
	ClientAddr    net.IP
	NextSeqSend   uint32
	NextSeqRecv   uint32
	Authenticated bool
	AuthToken     string
	CreatedAt     time.Time
	LastActivity  time.Time
	Streams       map[uint16]*Stream // Multiplexed streams within a session
	recvBuf       map[uint32]*TunnelPacket
	NextRecvSeq   uint32
	
	// NAT tracking
	LastICMPID      uint16
	LastICMPSeq     uint16
	OutboundICMPID  uint16
	OutboundICMPSeq uint16
	
	// Sliding Window & Congestion Control
	Mu            sync.RWMutex
	inflight      map[uint32]*inflightPacket
	cwnd          int
	ssthresh      int
	srtt          time.Duration
	rttvar        time.Duration
	rto           time.Duration

	// SACK state
	receivedSeqs  map[uint32]bool

	// ICMP Slot tracking (for NAT compatibility)
	icmpSlots chan icmpSlot

	// Cleanup
	Ctx    context.Context
	Cancel context.CancelFunc
}

type icmpSlot struct {
	ID  uint16
	Seq uint16
}

type inflightPacket struct {
	Pkt      *TunnelPacket
	SentAt   time.Time
	Retries  int
}

type SACK struct {
	AckedSeq uint32   // Highest in-order sequence received
	Blocks   []uint32 // Ranges of out-of-order blocks: [start1, end1, start2, end2, ...]
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
		recvBuf:       make(map[uint32]*TunnelPacket),
		NextRecvSeq:   0,
		inflight:      make(map[uint32]*inflightPacket),
		cwnd:          512, // Large initial window for high concurrency
		ssthresh:      2048,
		rto:           time.Second,
		receivedSeqs:  make(map[uint32]bool),
		icmpSlots:     make(chan icmpSlot, 8192), // Buffer up to 8192 slots for high concurrency
		OutboundICMPID: uint16(generateSessionID() & 0xFFFF),
		OutboundICMPSeq: 0,
	}

	// Check for existing session with same IP
	if old, ok := sm.sessionsByAddr[clientAddr.String()]; ok {
		if old.ID != id {
			sm.log.Info("Replacing old session %08x with %08x for client %s", old.ID, id, clientAddr)
			old.Close()
			delete(sm.sessions, old.ID)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	session.Ctx = ctx
	session.Cancel = cancel

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
		session.Close()
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
		session.Mu.Lock()
		session.LastActivity = time.Now()
		session.Mu.Unlock()
	}
}

// GetNextSeq returns and increments the send sequence number.
func (s *Session) GetNextSeq() uint32 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	seq := s.NextSeqSend
	s.NextSeqSend++
	return seq
}

// RecordSent records a packet as being in-flight.
func (s *Session) RecordSent(pkt *TunnelPacket) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	now := time.Now()
	s.inflight[pkt.SeqNum] = &inflightPacket{
		Pkt:    pkt,
		SentAt: now,
	}
	s.LastActivity = now // Keep session alive while sending
}

// ProcessACK handles an incoming ACK or SACK.
// Returns a list of newly acknowledged packets.
func (s *Session) ProcessACK(ackedSeq uint32, sackBlocks []uint32) []*TunnelPacket {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var acknowledged []*TunnelPacket

	// Simple cumulative ACK
	for seq, inflight := range s.inflight {
		// Circular distance check: seq is acked if (ackedSeq - seq) < 2^31
		if int32(ackedSeq-seq) >= 0 {
			acknowledged = append(acknowledged, inflight.Pkt)
			s.UpdateRTT(time.Since(inflight.SentAt))
			delete(s.inflight, seq)
		}
	}

	// SACK blocks
	for i := 0; i+1 < len(sackBlocks); i += 2 {
		start := sackBlocks[i]
		end := sackBlocks[i+1]
		// Loop from start to end in uint32 space
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
			s.cwnd += len(acknowledged) // Slow start: grow by ACKed count
		} else {
			// Congestion avoidance: more conservative growth
			growth := len(acknowledged) / 8
			if growth < 1 {
				growth = 1
			}
			s.cwnd += growth
		}
		
		// Cap cwnd to prevent buffer bloat/overflow (16MB buffer -> ~11000 pkts, so 4096 is safe ~5.7MB)
		if s.cwnd > 4096 {
			s.cwnd = 4096
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
	if s.rto < 50*time.Millisecond {
		s.rto = 50 * time.Millisecond
	}
	if s.rto > 3*time.Second {
		s.rto = 3 * time.Second
	}
}

// GetRetransmissions returns packets that have timed out.
func (s *Session) GetRetransmissions() []*TunnelPacket {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var retrans []*TunnelPacket
	now := time.Now()
	for seq, inflight := range s.inflight {
		// Clean up packets for closed streams
		if inflight.Pkt.Type == TypeData && len(inflight.Pkt.StreamIDs) > 0 {
			anyActive := false
			for _, sid := range inflight.Pkt.StreamIDs {
				if _, ok := s.Streams[sid]; ok {
					anyActive = true
					break
				}
			}
			if !anyActive {
				delete(s.inflight, seq)
				continue
			}
		}

		// Enforce retry limit (avoid infinite loops for dead clients)
		if inflight.Retries > 50 {
			delete(s.inflight, seq)
			continue
		}

		if now.Sub(inflight.SentAt) > s.rto {
			inflight.SentAt = now
			inflight.Retries++
			retrans = append(retrans, inflight.Pkt)
		}
	}

	if len(retrans) > 0 {
		// Mild congestion back-off for ICMP tunnel (localhost retransmissions
		// are usually scheduling delays, not real congestion)
		s.ssthresh = s.cwnd * 3 / 4
		if s.ssthresh < 64 {
			s.ssthresh = 64
		}
		// Very mild reduction: 7/8 of current cwnd
		newCwnd := s.cwnd * 7 / 8
		if newCwnd < s.ssthresh {
			newCwnd = s.ssthresh
		}
		s.cwnd = newCwnd
	}

	return retrans
}

// GetInflightCount returns the number of in-flight packets.
func (s *Session) GetInflightCount() int {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return len(s.inflight)
}

// GetCWND returns the current congestion window size.
func (s *Session) GetCWND() int {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.cwnd
}

// GenerateSACK creates a SACK message based on received packets.
func (s *Session) GenerateSACK() *SACK {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	sack := &SACK{
		AckedSeq: s.NextRecvSeq - 1,
	}

	var keys []uint32
	for seq := range s.receivedSeqs {
		// Circular distance check: include if seq is ahead of NextRecvSeq
		if int32(seq - s.NextRecvSeq) >= 0 {
			keys = append(keys, seq)
		}
	}
	if len(keys) == 0 {
		return sack
	}
	
	// Sort keys
	sort.Slice(keys, func(i, j int) bool {
		return int32(keys[i]-keys[j]) < 0
	})

	start := keys[0]
	end := keys[0]
	for i := 1; i < len(keys); i++ {
		if keys[i] == end+1 {
			end = keys[i]
		} else {
			sack.Blocks = append(sack.Blocks, start, end)
			start = keys[i]
			end = keys[i]
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

// MarkReceived records a sequence number as received and cleans up old state.
func (s *Session) MarkReceived(seq uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.receivedSeqs[seq] = true

	// Cleanup: periodically remove very old sequence numbers to keep map size sane
	if len(s.receivedSeqs) > 30000 {
		for s_seq := range s.receivedSeqs {
			if int32(s.NextRecvSeq-s_seq) > 20000 {
				delete(s.receivedSeqs, s_seq)
			}
		}
	}
}

// AddICMPSlot adds a new ICMP ID/Seq pair for use in responding.
func (s *Session) AddICMPSlot(id, seq uint16) {
	slot := icmpSlot{ID: id, Seq: seq}
	select {
	case s.icmpSlots <- slot:
	default:
		// Channel full? Drain one and add new (keep most recent)
		select {
		case <-s.icmpSlots:
		default:
		}
		select {
		case s.icmpSlots <- slot:
		default:
		}
	}
}

// GetICMPSlot returns a fresh ICMP ID/Seq pair, blocking if none available.
func (s *Session) GetICMPSlot(ctx context.Context) (uint16, uint16, error) {
	select {
	case slot := <-s.icmpSlots:
		return slot.ID, slot.Seq, nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	case <-s.Ctx.Done():
		return 0, 0, fmt.Errorf("session closed")
	}
}

// isOlder returns true if seq is older than base by more than threshold, considering wraparound.
func (s *Session) isOlder(seq, base uint32, threshold uint32) bool {
	diff := int32(base - seq)
	return diff > int32(threshold)
}

// IsDuplicate returns true if the sequence number has already been processed or is currently buffered.
func (s *Session) IsDuplicate(seq uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	
	if _, ok := s.recvBuf[seq]; ok {
		return true
	}
	
	// A positive signed diff means seq is behind NextRecvSeq (i.e., already processed).
	diff := int32(s.NextRecvSeq - seq)
	if diff > 0 {
		return true
	}
	
	return false
}

// GetNextICMPSeq returns and increments the outbound ICMP sequence number.
func (s *Session) GetNextICMPSeq() uint16 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	seq := s.OutboundICMPSeq
	s.OutboundICMPSeq++
	return seq
}

// ProcessIncoming handles sequence numbers and reordering.
// Returns a slice of packets that are now in-order and ready to be processed.
func (s *Session) ProcessIncoming(pkt *TunnelPacket) []*TunnelPacket {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.LastICMPID = pkt.ICMPID
	s.LastICMPSeq = pkt.ICMPSeq
	s.receivedSeqs[pkt.SeqNum] = true

	// If this is exactly what we expect
	if pkt.SeqNum == s.NextRecvSeq {
		s.NextRecvSeq++
		// Packets < NextRecvSeq are implicitly acked, so remove from map to keep it small
		delete(s.receivedSeqs, pkt.SeqNum)
		result := []*TunnelPacket{pkt}

		// Check buffer for subsequent packets
		for {
			if nextPkt, ok := s.recvBuf[s.NextRecvSeq]; ok {
				// Re-stamp buffered packets with triggering ID/Seq
				nextPkt.ICMPID = pkt.ICMPID
				nextPkt.ICMPSeq = pkt.ICMPSeq
				result = append(result, nextPkt)
				
				// Clean up maps
				delete(s.receivedSeqs, s.NextRecvSeq)
				delete(s.recvBuf, s.NextRecvSeq)
				s.NextRecvSeq++
			} else {
				break
			}
		}
		return result
	}

	// Out of order: buffer it if it's not too far ahead
	diff := int32(pkt.SeqNum - s.NextRecvSeq)
	if diff > 0 && diff < 10000 { // Max 10000 packets ahead
		s.recvBuf[pkt.SeqNum] = pkt
	}
	
	return nil
}

// Compress applies zlib compression to data.
func (s *Session) Compress(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// Decompress removes zlib compression from data.
func (s *Session) Decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// AddStream adds a new data stream to the session.
func (s *Session) AddStream(protocol, destination string) *Stream {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	id := uint16(len(s.Streams) + 1)
	stream := &Stream{
		ID:          id,
		Protocol:    protocol,
		Destination: destination,
		DataChan:    make(chan []byte, 4096),
		Done:        make(chan struct{}),
		CreatedAt:   time.Now(),
	}
	s.Streams[id] = stream
	return stream
}

// AddStreamWithID adds a new data stream to the session with a specific ID.
func (s *Session) AddStreamWithID(id uint16, protocol, destination string) *Stream {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	stream := &Stream{
		ID:          id,
		Protocol:    protocol,
		Destination: destination,
		DataChan:    make(chan []byte, 4096),
		Done:        make(chan struct{}),
		CreatedAt:   time.Now(),
	}
	s.Streams[id] = stream
	return stream
}

// RemoveStream removes a stream from the session.
func (s *Session) RemoveStream(id uint16) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

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
			session.Mu.Lock()
			if now.Sub(session.LastActivity) > sm.timeout {
				session.Mu.Unlock()
				sm.log.Info("Session %08x timed out (idle %v)", id, now.Sub(session.LastActivity))
				session.Close()
				delete(sm.sessionsByAddr, session.ClientAddr.String())
				delete(sm.sessions, id)
			} else {
				session.Mu.Unlock()
			}
		}
		sm.mu.Unlock()
	}
}

// Close terminates the session and all its streams.
func (s *Session) Close() {
	s.Mu.Lock()
	if s.Cancel != nil {
		s.Cancel()
	}
	// Close all streams
	for id, stream := range s.Streams {
		select {
		case <-stream.Done:
		default:
			close(stream.Done)
		}
		delete(s.Streams, id)
	}
	s.Mu.Unlock()
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

// EncodeControlMessage creates a simple control message with subtype and optional data value.
func EncodeControlMessage(subtype uint8, data uint32) []byte {
	buf := make([]byte, 5)
	buf[0] = subtype
	binary.BigEndian.PutUint32(buf[1:5], data)
	return buf
}

// DecodeControlMessage extracts subtype and data value from a control packet.
func DecodeControlMessage(data []byte) (subtype uint8, value uint32, err error) {
	if len(data) < 1 {
		return 0, 0, fmt.Errorf("control message too short")
	}
	subtype = data[0]
	if len(data) >= 5 {
		value = binary.BigEndian.Uint32(data[1:5])
	}
	return subtype, value, nil
}
// EncodeSACK serializes a SACK message.
func EncodeSACK(s *SACK) []byte {
	buf := make([]byte, 5+len(s.Blocks)*4)
	buf[0] = ControlSACK
	binary.BigEndian.PutUint32(buf[1:5], s.AckedSeq)
	for i, b := range s.Blocks {
		binary.BigEndian.PutUint32(buf[5+i*4:5+i*4+4], b)
	}
	return buf
}

// EncodePacket wraps a SACK in a TunnelPacket.
func (s *SACK) EncodePacket(sessionID uint32) *TunnelPacket {
	return &TunnelPacket{
		Type:      TypeControl,
		SessionID: sessionID,
		SeqNum:    0, // SACKs are not reliable themselves (sent frequently)
		Data:      EncodeSACK(s),
	}
}

// DecodeSACK deserializes a SACK message.
func DecodeSACK(data []byte) (*SACK, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("SACK too short")
	}
	s := &SACK{
		AckedSeq: binary.BigEndian.Uint32(data[1:5]),
	}
	for i := 5; i+3 < len(data); i += 4 {
		s.Blocks = append(s.Blocks, binary.BigEndian.Uint32(data[i:i+4]))
	}
	return s, nil
}
