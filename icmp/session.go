package icmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pierrec/lz4/v4"

	"github.com/imamirmhd/icmptunnel/logger"
)

// ---- Compression Pools ----

var lz4WriterPool = sync.Pool{
	New: func() interface{} {
		w := lz4.NewWriter(nil)
		return w
	},
}

var lz4ReaderPool = sync.Pool{
	New: func() interface{} {
		return lz4.NewReader(nil)
	},
}

var compressBufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// ---- Session ----

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
	PushICMPID      uint16
	LastSrcIP       net.IP
	LastRouteFlag   uint8
	LastRelayIP     net.IP

	// Sliding Window & Congestion Control
	Mu       sync.RWMutex
	inflight map[uint32]*inflightPacket
	cwnd     int
	ssthresh int
	srtt     time.Duration
	rttvar   time.Duration
	rto      time.Duration

	// Fast retransmit tracking
	dupAckCount  map[uint32]int // seq -> duplicate ACK count
	lastAckedSeq uint32

	// SACK state - bounded ring buffer
	receivedSeqs   map[uint32]bool
	recvSeqCleanup uint32 // counter for periodic cleanup

	// ICMP Slot tracking (for NAT compatibility)
	icmpSlots chan icmpSlot

	// Cleanup
	Ctx    context.Context
	Cancel context.CancelFunc

	// Condition variable for send capacity signaling
	sendCapCh chan struct{}

	// Stats (atomic - lock-free)
	StatsTxPackets   uint64
	StatsRxPackets   uint64
	StatsTxBytes     uint64
	StatsRxBytes     uint64
	StatsRetransmits uint64
	StatsLossRate    uint64 // fixed-point: value/10000 = rate
	StatsCWND        uint64
	StatsInflight    uint64
	StatsRTT         uint64 // nanoseconds

	// Session state for zero-downtime reconnect
	StateSnapshot *SessionSnapshot
}

// SessionSnapshot captures session state for fast recovery.
type SessionSnapshot struct {
	SessionID   uint32
	NextSeqSend uint32
	NextSeqRecv uint32
	AuthToken   string
	StreamIDs   []uint16
	Timestamp   time.Time
}

type icmpSlot struct {
	ID  uint16
	Seq uint16
}

type inflightPacket struct {
	Pkt      *TunnelPacket
	SentAt   time.Time
	Retries  int
	Priority uint8 // 0=data, 1=control, 2=critical
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
	State       uint8
	Priority    uint8 // 0=normal, 1=high (control/streaming)

	// Per-stream stats
	TxBytes uint64
	RxBytes uint64

	// Crash guard
	closeOnce sync.Once
}

const (
	StreamStateConnecting uint8 = 0
	StreamStateOpen       uint8 = 1
	StreamStateClosing    uint8 = 2
	StreamStateClosed     uint8 = 3
)

// SessionManager manages multiple tunnel sessions.
type SessionManager struct {
	sessions       map[uint32]*Session
	sessionsByAddr map[string]*Session
	mu             sync.RWMutex
	log            *logger.Logger
	timeout        time.Duration
	defaultCWND    int
	defaultSST     int

	// Session snapshots for zero-downtime reconnect
	snapshots map[uint32]*SessionSnapshot
	snapMu    sync.RWMutex
}

// NewSessionManager creates a new session manager.
func NewSessionManager(timeout time.Duration) *SessionManager {
	return NewSessionManagerWithParams(timeout, 2048, 8192)
}

func NewSessionManagerWithParams(timeout time.Duration, cwnd, ssthresh int) *SessionManager {
	sm := &SessionManager{
		sessions:       make(map[uint32]*Session),
		sessionsByAddr: make(map[string]*Session),
		snapshots:      make(map[uint32]*SessionSnapshot),
		log:            logger.Default().WithComponent("session-mgr"),
		timeout:        timeout,
		defaultCWND:    cwnd,
		defaultSST:     ssthresh,
	}
	go sm.cleanupLoop()
	return sm
}

// CreateSessionWithID creates a new session with a specific ID.
func (sm *SessionManager) CreateSessionWithID(clientAddr net.IP, id uint32) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if old, ok := sm.sessions[id]; ok {
		sm.log.Info("Replacing existing session %08x for client %s", id, clientAddr)
		// Save snapshot for potential resume
		sm.saveSnapshotLocked(old)
		delete(sm.sessionsByAddr, old.ClientAddr.String())
		old.Close()
	}

	now := time.Now()
	session := &Session{
		ID:              id,
		ClientAddr:      clientAddr,
		CreatedAt:       now,
		LastActivity:    now,
		Streams:         make(map[uint16]*Stream),
		recvBuf:         make(map[uint32]*TunnelPacket),
		NextSeqSend:     0,
		NextRecvSeq:     0,
		inflight:        make(map[uint32]*inflightPacket),
		dupAckCount:     make(map[uint32]int),
		cwnd:            sm.defaultCWND,
		ssthresh:        sm.defaultSST,
		rto:             500 * time.Millisecond,
		receivedSeqs:    make(map[uint32]bool),
		icmpSlots:       make(chan icmpSlot, 65536),
		OutboundICMPID:  uint16(generateSessionID() & 0xFFFF),
		OutboundICMPSeq: 0,
		PushICMPID:      uint16(generateSessionID() & 0xFFFF),
		sendCapCh:       make(chan struct{}, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	session.Ctx = ctx
	session.Cancel = cancel

	sm.sessions[id] = session
	sm.sessionsByAddr[clientAddr.String()] = session
	sm.log.Info("Created session %08x for client %s (cwnd=%d, ssthresh=%d)", id, clientAddr, sm.defaultCWND, sm.defaultSST)
	return session
}

func (sm *SessionManager) saveSnapshotLocked(s *Session) {
	s.Mu.RLock()
	streamIDs := make([]uint16, 0, len(s.Streams))
	for id := range s.Streams {
		streamIDs = append(streamIDs, id)
	}
	s.Mu.RUnlock()

	snap := &SessionSnapshot{
		SessionID:   s.ID,
		NextSeqSend: s.NextSeqSend,
		NextSeqRecv: s.NextRecvSeq,
		AuthToken:   s.AuthToken,
		StreamIDs:   streamIDs,
		Timestamp:   time.Now(),
	}

	sm.snapMu.Lock()
	sm.snapshots[s.ID] = snap
	sm.snapMu.Unlock()
}

// GetSnapshot returns a session snapshot for resume, if available.
func (sm *SessionManager) GetSnapshot(id uint32) *SessionSnapshot {
	sm.snapMu.RLock()
	defer sm.snapMu.RUnlock()
	snap := sm.snapshots[id]
	if snap != nil && time.Since(snap.Timestamp) > 5*time.Minute {
		return nil // Too old
	}
	return snap
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
		sm.saveSnapshotLocked(session)
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
	priority := uint8(0)
	if pkt.Type == TypeControl {
		priority = 1
		if len(pkt.Data) > 0 {
			sub := pkt.Data[0]
			if sub == ControlConnect || sub == ControlAuthOK || sub == ControlAuthFail || sub == ControlClose {
				priority = 2 // Critical
			}
		}
	}
	s.inflight[pkt.SeqNum] = &inflightPacket{
		Pkt:      pkt,
		SentAt:   now,
		Priority: priority,
	}
	s.LastActivity = now
	atomic.AddUint64(&s.StatsTxPackets, 1)
	atomic.AddUint64(&s.StatsTxBytes, uint64(len(pkt.Data)))
	atomic.StoreUint64(&s.StatsInflight, uint64(len(s.inflight)))
}

// ProcessACK handles an incoming ACK or SACK.
// Returns a list of newly acknowledged packets.
func (s *Session) ProcessACK(ackedSeq uint32, sackBlocks []uint32) []*TunnelPacket {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var acknowledged []*TunnelPacket

	// Cumulative ACK
	for seq, inflight := range s.inflight {
		if int32(ackedSeq-seq) >= 0 {
			acknowledged = append(acknowledged, inflight.Pkt)
			s.UpdateRTTLocked(time.Since(inflight.SentAt))
			delete(s.inflight, seq)
			delete(s.dupAckCount, seq)
		}
	}

	// SACK blocks
	for i := 0; i+1 < len(sackBlocks); i += 2 {
		start := sackBlocks[i]
		end := sackBlocks[i+1]
		for seq := start; ; {
			if inflight, ok := s.inflight[seq]; ok {
				acknowledged = append(acknowledged, inflight.Pkt)
				s.UpdateRTTLocked(time.Since(inflight.SentAt))
				delete(s.inflight, seq)
				delete(s.dupAckCount, seq)
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
			// Slow start: grow by ACKed count (exponential growth)
			s.cwnd += len(acknowledged)
		} else {
			// Congestion avoidance: conservative linear growth
			growth := len(acknowledged) / 4
			if growth < 1 {
				growth = 1
			}
			s.cwnd += growth
		}

		// Cap cwnd
		if s.cwnd > 16384 {
			s.cwnd = 16384
		}

		// Signal send capacity availability
		select {
		case s.sendCapCh <- struct{}{}:
		default:
		}

		// Update stats
		atomic.StoreUint64(&s.StatsCWND, uint64(s.cwnd))
		atomic.StoreUint64(&s.StatsInflight, uint64(len(s.inflight)))
	}

	// Track for fast retransmit
	s.lastAckedSeq = ackedSeq

	return acknowledged
}

// UpdateRTTLocked updates RTT estimates. Must be called with Mu held.
func (s *Session) UpdateRTTLocked(measured time.Duration) {
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
	if s.rto < 25*time.Millisecond {
		s.rto = 25 * time.Millisecond
	}
	if s.rto > 10*time.Second {
		s.rto = 10 * time.Second
	}
	atomic.StoreUint64(&s.StatsRTT, uint64(s.srtt.Nanoseconds()))
}

// UpdateRTT updates RTT estimates (public, acquires lock).
func (s *Session) UpdateRTT(measured time.Duration) {
	s.Mu.Lock()
	s.UpdateRTTLocked(measured)
	s.Mu.Unlock()
}

// GetRetransmissions returns packets that have timed out or need fast retransmit.
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

		// Enforce retry limit
		maxRetries := 30
		if inflight.Priority >= 2 {
			maxRetries = 100 // Critical packets get more retries
		}
		if inflight.Retries > maxRetries {
			delete(s.inflight, seq)
			continue
		}

		// Timeout-based retransmit
		if now.Sub(inflight.SentAt) > s.rto {
			inflight.SentAt = now
			inflight.Retries++
			retrans = append(retrans, inflight.Pkt)
			atomic.AddUint64(&s.StatsRetransmits, 1)
		}
	}

	if len(retrans) > 0 {
		// Mild congestion back-off
		s.ssthresh = s.cwnd * 3 / 4
		if s.ssthresh < 128 {
			s.ssthresh = 128
		}
		newCwnd := s.cwnd * 7 / 8
		if newCwnd < s.ssthresh {
			newCwnd = s.ssthresh
		}
		s.cwnd = newCwnd
		atomic.StoreUint64(&s.StatsCWND, uint64(s.cwnd))
	}

	// Sort by priority (critical first)
	sort.Slice(retrans, func(i, j int) bool {
		pi, pj := uint8(0), uint8(0)
		if inf, ok := s.inflight[retrans[i].SeqNum]; ok {
			pi = inf.Priority
		}
		if inf, ok := s.inflight[retrans[j].SeqNum]; ok {
			pj = inf.Priority
		}
		return pi > pj
	})

	return retrans
}

// FastRetransmit handles duplicate ACK detection and triggers immediate retransmit.
// Returns packets that should be retransmitted immediately.
func (s *Session) FastRetransmit(ackedSeq uint32) []*TunnelPacket {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var retrans []*TunnelPacket
	nextSeq := ackedSeq + 1

	s.dupAckCount[nextSeq]++
	if s.dupAckCount[nextSeq] >= 3 {
		// 3 duplicate ACKs -> fast retransmit
		if inflight, ok := s.inflight[nextSeq]; ok {
			inflight.SentAt = time.Now()
			inflight.Retries++
			retrans = append(retrans, inflight.Pkt)
			atomic.AddUint64(&s.StatsRetransmits, 1)
		}
		delete(s.dupAckCount, nextSeq)

		// Fast recovery: halve cwnd
		s.ssthresh = s.cwnd / 2
		if s.ssthresh < 128 {
			s.ssthresh = 128
		}
		s.cwnd = s.ssthresh
		atomic.StoreUint64(&s.StatsCWND, uint64(s.cwnd))
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

// GetRTT returns the current smoothed RTT.
func (s *Session) GetRTT() time.Duration {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.srtt
}

// GetRTO returns the current retransmission timeout.
func (s *Session) GetRTO() time.Duration {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.rto
}

// GenerateSACK creates a SACK message based on received packets.
func (s *Session) GenerateSACK() *SACK {
	s.Mu.RLock()
	defer s.Mu.RUnlock()

	sack := &SACK{
		AckedSeq: s.NextRecvSeq - 1,
	}

	var keys []uint32
	for seq := range s.receivedSeqs {
		if int32(seq-s.NextRecvSeq) >= 0 {
			keys = append(keys, seq)
		}
	}
	if len(keys) == 0 {
		return sack
	}

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

	// Bounded cleanup: keep map under 65536 entries
	s.recvSeqCleanup++
	if s.recvSeqCleanup%1000 == 0 && len(s.receivedSeqs) > 65536 {
		for sSeq := range s.receivedSeqs {
			if int32(s.NextRecvSeq-sSeq) > 32768 {
				delete(s.receivedSeqs, sSeq)
			}
		}
	}
}

// UpdateNATInfo records the network path to the client.
func (s *Session) UpdateNATInfo(srcIP net.IP, routeFlag uint8, relayIP net.IP) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.LastSrcIP = srcIP
	s.LastRouteFlag = routeFlag
	s.LastRelayIP = relayIP
}

// AddICMPSlot adds a new ICMP ID/Seq pair for use in responding.
func (s *Session) AddICMPSlot(id, seq uint16) {
	slot := icmpSlot{ID: id, Seq: seq}
	select {
	case s.icmpSlots <- slot:
	default:
		// Channel full: drain oldest and add new
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

// isOlder returns true if seq is older than base by more than threshold.
func (s *Session) isOlder(seq, base uint32, threshold uint32) bool {
	diff := int32(base - seq)
	return diff > int32(threshold)
}

// IsDuplicate returns true if the sequence number has already been processed.
func (s *Session) IsDuplicate(seq uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if _, ok := s.recvBuf[seq]; ok {
		return true
	}

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
	atomic.AddUint64(&s.StatsRxPackets, 1)
	atomic.AddUint64(&s.StatsRxBytes, uint64(len(pkt.Data)))

	if pkt.SeqNum == s.NextRecvSeq {
		s.NextRecvSeq++
		delete(s.receivedSeqs, pkt.SeqNum)
		result := []*TunnelPacket{pkt}

		// Drain buffer for subsequent in-order packets
		for {
			if nextPkt, ok := s.recvBuf[s.NextRecvSeq]; ok {
				nextPkt.ICMPID = pkt.ICMPID
				nextPkt.ICMPSeq = pkt.ICMPSeq
				result = append(result, nextPkt)
				delete(s.receivedSeqs, s.NextRecvSeq)
				delete(s.recvBuf, s.NextRecvSeq)
				s.NextRecvSeq++
			} else {
				break
			}
		}
		return result
	}

	// Out of order: buffer if not too far ahead
	diff := int32(pkt.SeqNum - s.NextRecvSeq)
	if diff > 0 && diff < 20000 {
		s.recvBuf[pkt.SeqNum] = pkt
	}

	return nil
}

// ---- Compression (LZ4 - 10x faster than zlib) ----

// Compress applies LZ4 compression to data.
func (s *Session) Compress(data []byte) []byte {
	buf := compressBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer compressBufPool.Put(buf)

	w := lz4WriterPool.Get().(*lz4.Writer)
	w.Reset(buf)
	defer lz4WriterPool.Put(w)

	w.Write(data)
	w.Close()

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result
}

// Decompress removes LZ4 compression from data.
func (s *Session) Decompress(data []byte) ([]byte, error) {
	r := lz4ReaderPool.Get().(*lz4.Reader)
	r.Reset(bytes.NewReader(data))
	defer lz4ReaderPool.Put(r)

	result, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ---- Stream Management ----

// AddStream adds a new data stream to the session.
func (s *Session) AddStream(protocol, destination string) *Stream {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	id := uint16(len(s.Streams) + 1)
	stream := &Stream{
		ID:          id,
		Protocol:    protocol,
		Destination: destination,
		DataChan:    make(chan []byte, 8192),
		Done:        make(chan struct{}),
		CreatedAt:   time.Now(),
	}
	s.Streams[id] = stream
	return stream
}

// SetState sets the stream state.
func (s *Stream) SetState(state uint8) {
	s.State = state
}

// SafeClose closes the stream's Done channel exactly once (crash guard).
func (s *Stream) SafeClose() {
	s.closeOnce.Do(func() {
		close(s.Done)
	})
}

// AddStreamWithID adds a new data stream to the session with a specific ID.
func (s *Session) AddStreamWithID(id uint16, protocol, destination string) *Stream {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	stream := &Stream{
		ID:          id,
		Protocol:    protocol,
		Destination: destination,
		DataChan:    make(chan []byte, 32768),
		Done:        make(chan struct{}),
		CreatedAt:   time.Now(),
		State:       StreamStateConnecting,
	}
	s.Streams[id] = stream
	return stream
}

// RemoveStream removes a stream from the session.
func (s *Session) RemoveStream(id uint16) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if stream, ok := s.Streams[id]; ok {
		stream.SafeClose()
		delete(s.Streams, id)
	}
}

// Iterate calls f for each active session.
func (sm *SessionManager) Iterate(f func(*Session)) {
	sm.mu.RLock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	sm.mu.RUnlock()

	for _, s := range sessions {
		f(s)
	}
}

// cleanupLoop periodically removes timed-out sessions and stale snapshots.
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
				sm.saveSnapshotLocked(session)
				session.Close()
				delete(sm.sessionsByAddr, session.ClientAddr.String())
				delete(sm.sessions, id)
			} else {
				session.Mu.Unlock()
			}
		}
		sm.mu.Unlock()

		// Clean old snapshots
		sm.snapMu.Lock()
		for id, snap := range sm.snapshots {
			if time.Since(snap.Timestamp) > 10*time.Minute {
				delete(sm.snapshots, id)
			}
		}
		sm.snapMu.Unlock()
	}
}

// Close terminates the session and all its streams.
func (s *Session) Close() {
	s.Mu.Lock()
	s.Authenticated = false
	if s.Cancel != nil {
		s.Cancel()
	}
	// Close all streams with crash guard
	for id, stream := range s.Streams {
		stream.SafeClose()
		delete(s.Streams, id)
	}
	s.Mu.Unlock()
}

// TakeSnapshot creates a snapshot of current session state.
func (s *Session) TakeSnapshot() *SessionSnapshot {
	s.Mu.RLock()
	defer s.Mu.RUnlock()

	streamIDs := make([]uint16, 0, len(s.Streams))
	for id := range s.Streams {
		streamIDs = append(streamIDs, id)
	}

	return &SessionSnapshot{
		SessionID:   s.ID,
		NextSeqSend: s.NextSeqSend,
		NextSeqRecv: s.NextRecvSeq,
		AuthToken:   s.AuthToken,
		StreamIDs:   streamIDs,
		Timestamp:   time.Now(),
	}
}

// ActiveSessions returns the number of active sessions.
func (sm *SessionManager) ActiveSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetSessionIDByAddr returns the current SessionID for a client IP.
func (sm *SessionManager) GetSessionIDByAddr(addr net.IP) uint32 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if session, ok := sm.sessionsByAddr[addr.String()]; ok {
		return session.ID
	}
	return 0
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

// ---- Connect Request ----

type ConnectRequest struct {
	StreamID    uint16
	Protocol    string
	Destination string
}

func EncodeConnectRequest(req *ConnectRequest) []byte {
	protoBytes := []byte(req.Protocol)
	destBytes := []byte(req.Destination)
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

// ---- Control Messages ----

func EncodeControlMessage(subtype uint8, data uint32) []byte {
	buf := make([]byte, 5)
	buf[0] = subtype
	binary.BigEndian.PutUint32(buf[1:5], data)
	return buf
}

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

// ---- SACK Encoding/Decoding ----

func EncodeSACK(s *SACK) []byte {
	buf := make([]byte, 5+len(s.Blocks)*4)
	buf[0] = ControlSACK
	binary.BigEndian.PutUint32(buf[1:5], s.AckedSeq)
	for i, b := range s.Blocks {
		binary.BigEndian.PutUint32(buf[5+i*4:5+i*4+4], b)
	}
	return buf
}

func (s *SACK) EncodePacket(sessionID uint32) *TunnelPacket {
	return &TunnelPacket{
		Type:      TypeControl,
		SessionID: sessionID,
		SeqNum:    0,
		Data:      EncodeSACK(s),
	}
}

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

// ---- Send Capacity (No goroutine leak) ----

// WaitSendCapacity blocks until the session has window availability to send.
// Uses channel-based signaling to avoid goroutine leaks.
func (s *Session) WaitSendCapacity(ctx context.Context) error {
	s.Mu.RLock()
	if len(s.inflight) < s.cwnd {
		s.Mu.RUnlock()
		return nil
	}
	s.Mu.RUnlock()

	// Wait for capacity signal or context cancellation
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.Ctx.Done():
			return fmt.Errorf("session closed")
		case <-s.sendCapCh:
			s.Mu.RLock()
			if len(s.inflight) < s.cwnd {
				s.Mu.RUnlock()
				return nil
			}
			s.Mu.RUnlock()
			// Still full, loop again
		case <-time.After(100 * time.Millisecond):
			s.Mu.RLock()
			if len(s.inflight) < s.cwnd {
				s.Mu.RUnlock()
				return nil
			}
			s.Mu.RUnlock()
		}
	}
}

// ---- Stats ----

// SessionStats holds real-time session metrics.
type SessionStats struct {
	TxPackets   uint64
	RxPackets   uint64
	TxBytes     uint64
	RxBytes     uint64
	Retransmits uint64
	LossRate    float64
	CWND        int
	Inflight    int
	RTT         time.Duration
	RTO         time.Duration
	Streams     int
}

// GetStats returns current session statistics.
func (s *Session) GetStats() SessionStats {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return SessionStats{
		TxPackets:   atomic.LoadUint64(&s.StatsTxPackets),
		RxPackets:   atomic.LoadUint64(&s.StatsRxPackets),
		TxBytes:     atomic.LoadUint64(&s.StatsTxBytes),
		RxBytes:     atomic.LoadUint64(&s.StatsRxBytes),
		Retransmits: atomic.LoadUint64(&s.StatsRetransmits),
		LossRate:    float64(atomic.LoadUint64(&s.StatsLossRate)) / 10000.0,
		CWND:        s.cwnd,
		Inflight:    len(s.inflight),
		RTT:         s.srtt,
		RTO:         s.rto,
		Streams:     len(s.Streams),
	}
}

// ---- Load Shedding ----

// ShouldShed returns true if the session is under extreme load and should drop low-priority traffic.
func (s *Session) ShouldShed() bool {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	// Shed if inflight > 2x cwnd (severe overload)
	return len(s.inflight) > s.cwnd*2
}

// GetLowestPriorityStream returns the stream with lowest priority for shedding.
func (s *Session) GetLowestPriorityStream() uint16 {
	s.Mu.RLock()
	defer s.Mu.RUnlock()

	var lowestPri uint8 = 255
	var lowestID uint16 = 0
	for id, stream := range s.Streams {
		if stream.Priority < lowestPri {
			lowestPri = stream.Priority
			lowestID = id
		}
	}
	return lowestID
}
