package icmp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

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
	mu            sync.Mutex
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
		CreatedAt:    now,
		LastActivity: now,
		Streams:      make(map[uint16]*Stream),
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
	buf := make([]byte, 2+1+len(protoBytes)+2+len(destBytes)+1)

	binary.BigEndian.PutUint16(buf[0:2], req.StreamID)
	buf[2] = byte(len(protoBytes))
	copy(buf[3:3+len(protoBytes)], protoBytes)
	off := 3 + len(protoBytes)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(destBytes)))
	copy(buf[off+2:], destBytes)
	buf[len(buf)-1] = ControlConnect // subtype marker

	return buf
}

// DecodeConnectRequest deserializes a connect request.
func DecodeConnectRequest(data []byte) (*ConnectRequest, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("connect request too short")
	}

	req := &ConnectRequest{}
	req.StreamID = binary.BigEndian.Uint16(data[0:2])
	protoLen := int(data[2])
	if len(data) < 3+protoLen+2 {
		return nil, fmt.Errorf("connect request truncated at protocol")
	}
	req.Protocol = string(data[3 : 3+protoLen])
	off := 3 + protoLen
	destLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	if len(data) < off+2+destLen {
		return nil, fmt.Errorf("connect request truncated at destination")
	}
	req.Destination = string(data[off+2 : off+2+destLen])

	return req, nil
}
