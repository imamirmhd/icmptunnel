package tunnel

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/user/icmptunnel/auth"
	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/crypto"
	"github.com/user/icmptunnel/evasion"
	"github.com/user/icmptunnel/icmp"
	"github.com/user/icmptunnel/logger"
)

// Server manages the server side of the ICMP tunnel.
type Server struct {
	cfg        *config.ServerConfig
	socket     *icmp.Socket
	encryptor  crypto.Encryptor
	evasion    *evasion.Manager
	sessionMgr *icmp.SessionManager
	authValidator *auth.Validator
	connections map[string]net.Conn // streamKey -> connection
	connMu     sync.RWMutex
	log        *logger.Logger
	done       chan struct{}
	wg         sync.WaitGroup
}

// NewServer creates a new tunnel server.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("server")

	readTimeout, _ := time.ParseDuration(cfg.ICMP.ReadTimeout)
	writeTimeout, _ := time.ParseDuration(cfg.ICMP.WriteTimeout)
	if readTimeout == 0 {
		readTimeout = 5 * time.Second
	}
	if writeTimeout == 0 {
		writeTimeout = 5 * time.Second
	}

	sock, err := icmp.NewSocket(cfg.ICMP.MaxPacketSize, cfg.ICMP.TTL, readTimeout, writeTimeout)
	if err != nil {
		return nil, fmt.Errorf("creating ICMP socket: %w", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, fmt.Errorf("binding socket: %w", err)
	}

	var enc crypto.Encryptor
	if cfg.Encryption.Enabled {
		key, err := hex.DecodeString(cfg.Encryption.Key)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("decoding encryption key: %w", err)
		}
		enc, err = crypto.NewEncryptor(cfg.Encryption.Method, key)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("creating encryptor: %w", err)
		}
		log.Info("Encryption enabled: %s", enc.Name())
	} else {
		enc = &crypto.NopEncryptor{}
	}

	ev := evasion.NewManager(cfg.Evasion)
	validator := auth.NewValidator(cfg.AuthTokens)

	return &Server{
		cfg:           cfg,
		socket:        sock,
		encryptor:     enc,
		evasion:       ev,
		sessionMgr:    icmp.NewSessionManager(5 * time.Minute),
		authValidator: validator,
		connections:   make(map[string]net.Conn),
		log:           log,
		done:          make(chan struct{}),
	}, nil
}

// Start runs the tunnel server.
func (s *Server) Start() error {
	s.log.Info("Starting ICMP tunnel server on %s", s.cfg.Listen)

	// Configure firewall settings
	if s.cfg.Firewall.DisableEchoReply {
		s.disableEchoReply()
	}
	if s.cfg.Firewall.EnableForwarding {
		s.enableIPForwarding()
	}

	// Start receive loop
	s.wg.Add(1)
	go s.receiveLoop()

	return nil
}

// Stop shuts down the tunnel server.
func (s *Server) Stop() {
	s.log.Info("Stopping tunnel server")
	close(s.done)

	// Close all forwarding connections
	s.connMu.Lock()
	for key, conn := range s.connections {
		conn.Close()
		delete(s.connections, key)
	}
	s.connMu.Unlock()

	s.socket.Close()
	s.wg.Wait()

	// Restore echo reply
	if s.cfg.Firewall.DisableEchoReply {
		s.enableEchoReply()
	}
}

// Wait blocks until the server is stopped.
func (s *Server) Wait() {
	c := make(chan struct{})
	<-c // Block forever until Stop is called
}

func (s *Server) receiveLoop() {
	defer s.wg.Done()

	fragBuf := evasion.NewFragmentBuffer()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		srcIP, icmpType, rawPayload, err := s.socket.Receive()
		if err != nil {
			// Don't log timeouts to avoid spam, unless we want to debug headers
			if err.Error() != "receiving: resource temporarily unavailable" {
				s.log.Debug("Receive error: %v", err)
			}
			continue
		}

		// Only process echo requests (from clients) or echo replies (from relay)
		if icmpType != 8 && icmpType != 0 {
			continue
		}

		s.log.Debug("Received %d bytes from %s (type %d)", len(rawPayload), srcIP, icmpType)

		// Check for spoofed packets
		var realClientIP net.IP
		var tunnelPayload []byte
		var routeFlag uint8
		var relayIP net.IP

		if s.cfg.Relay.Enabled {
			spoofHdr, data, err := icmp.ExtractSpoofedPayload(rawPayload)
			if err == nil && spoofHdr != nil {
				realClientIP = spoofHdr.RealClientIP
				routeFlag = spoofHdr.RouteFlag
				relayIP = spoofHdr.RelayIP
				tunnelPayload = data
			} else {
				realClientIP = srcIP
				tunnelPayload = rawPayload
			}
		} else {
			realClientIP = srcIP
			tunnelPayload = rawPayload
		}

		// Try defragmenting
		var decryptedPayload []byte
		data, complete, fErr := fragBuf.Add(tunnelPayload)
		if fErr != nil || !complete {
			if fErr == nil {
				continue
			}
			decryptedPayload, err = s.encryptor.Decrypt(tunnelPayload)
			if err != nil {
				s.log.Debug("Decryption failed from %s: %v", srcIP, err)
				continue
			}
		} else {
			decryptedPayload, err = s.encryptor.Decrypt(data)
			if err != nil {
				s.log.Debug("Decryption failed (fragmented) from %s: %v", srcIP, err)
				continue
			}
		}

		tunnelPkt, err := icmp.DecodeTunnelPacket(decryptedPayload)
		if err != nil {
			s.log.Debug("Decode tunnel packet failed: %v", err)
			continue
		}

		s.handlePacket(realClientIP, srcIP, routeFlag, relayIP, tunnelPkt)
	}
}

func (s *Server) handlePacket(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, pkt *icmp.TunnelPacket) {
	s.log.Debug("Handling packet type %d, session %08x, seq %d", pkt.Type, pkt.SessionID, pkt.SeqNum)
	switch pkt.Type {
	case icmp.TypeAuth:
		s.handleAuth(clientIP, srcIP, routeFlag, relayIP, pkt)

	case icmp.TypeData:
		session := s.sessionMgr.GetSession(pkt.SessionID)
		if session == nil || !session.Authenticated {
			s.log.Warn("Data from unauthenticated session %08x", pkt.SessionID)
			return
		}
		s.sessionMgr.TouchSession(pkt.SessionID)
		s.handleData(clientIP, srcIP, routeFlag, relayIP, session, pkt)

	case icmp.TypeControl:
		session := s.sessionMgr.GetSession(pkt.SessionID)
		if session == nil || !session.Authenticated {
			return
		}
		s.sessionMgr.TouchSession(pkt.SessionID)
		s.handleControl(clientIP, srcIP, routeFlag, relayIP, session, pkt)

	case icmp.TypeDiag:
		s.handleDiag(clientIP, srcIP, routeFlag, relayIP, pkt)
	}
}

func (s *Server) handleAuth(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, pkt *icmp.TunnelPacket) {
	token := string(pkt.Data)
	s.log.Info("Auth request from %s (session %08x)", clientIP, pkt.SessionID)

	var responseSubtype uint8
	if s.authValidator.IsValid(token) {
		session := s.sessionMgr.CreateSessionWithID(clientIP, pkt.SessionID)
		session.Authenticated = true
		session.AuthToken = token
		responseSubtype = icmp.ControlAuthOK
		s.log.Info("Authentication successful for %s", clientIP)
	} else {
		responseSubtype = icmp.ControlAuthFail
		s.log.Warn("Authentication failed for %s", clientIP)
	}

	responsePkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: pkt.SessionID,
		SeqNum:    0,
		Data:      []byte{responseSubtype},
	}

	s.sendResponse(clientIP, srcIP, routeFlag, relayIP, responsePkt)
}

func (s *Server) handleData(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, session *icmp.Session, pkt *icmp.TunnelPacket) {
	streamID, data, err := icmp.DecodeStreamData(pkt.Data)
	if err != nil {
		s.log.Error("Decode stream data: %v", err)
		return
	}

	connKey := fmt.Sprintf("%s:%d", clientIP, streamID)

	s.connMu.RLock()
	conn, exists := s.connections[connKey]
	s.connMu.RUnlock()

	if !exists {
		s.log.Warn("Data for unknown stream %s", connKey)
		return
	}

	if _, err := conn.Write(data); err != nil {
		s.log.Error("Write to destination: %v", err)
		s.connMu.Lock()
		conn.Close()
		delete(s.connections, connKey)
		s.connMu.Unlock()
	}
}

func (s *Server) handleControl(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, session *icmp.Session, pkt *icmp.TunnelPacket) {
	req, err := icmp.DecodeConnectRequest(pkt.Data)
	if err != nil {
		s.log.Error("Decode connect request: %v", err)
		return
	}

	s.log.Info("Connect request: stream=%d proto=%s dest=%s from %s",
		req.StreamID, req.Protocol, req.Destination, clientIP)

	// Establish connection to destination
	var conn net.Conn
	switch req.Protocol {
	case "tcp":
		conn, err = net.DialTimeout("tcp", req.Destination, 10*time.Second)
	case "udp":
		conn, err = net.DialTimeout("udp", req.Destination, 10*time.Second)
	default:
		s.log.Error("Unsupported protocol: %s", req.Protocol)
		return
	}

	if err != nil {
		s.log.Error("Connect to %s failed: %v", req.Destination, err)
		return
	}

	connKey := fmt.Sprintf("%s:%d", clientIP, req.StreamID)
	s.connMu.Lock()
	s.connections[connKey] = conn
	s.connMu.Unlock()

	// Send connect ACK
	ackPkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: session.ID,
		Data:      []byte{icmp.ControlConnectACK},
	}
	s.sendResponse(clientIP, srcIP, routeFlag, relayIP, ackPkt)

	// Start reading from destination and sending back
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.connMu.Lock()
			delete(s.connections, connKey)
			s.connMu.Unlock()
			conn.Close()
		}()

		buf := make([]byte, 32*1024)
		for {
			select {
			case <-s.done:
				return
			default:
			}

			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.log.Error("Read from %s: %v", req.Destination, err)
				}
				return
			}

			streamData := icmp.EncodeStreamData(req.StreamID, buf[:n])
			dataPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeData,
				SessionID: session.ID,
				SeqNum:    session.GetNextSeq(),
				Data:      streamData,
			}

			s.sendResponse(clientIP, srcIP, routeFlag, relayIP, dataPkt)
		}
	}()
}

func (s *Server) handleDiag(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, pkt *icmp.TunnelPacket) {
	// Echo back diagnostic data with server timestamp
	responsePkt := &icmp.TunnelPacket{
		Type:      icmp.TypeDiag,
		SessionID: pkt.SessionID,
		SeqNum:    pkt.SeqNum,
		Data:      pkt.Data,
	}
	s.sendResponse(clientIP, srcIP, routeFlag, relayIP, responsePkt)
}

func (s *Server) sendResponse(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, pkt *icmp.TunnelPacket) {
	payload := pkt.Encode()

	encrypted, err := s.encryptor.Encrypt(payload)
	if err != nil {
		s.log.Error("Encrypt response: %v", err)
		return
	}

	// Apply evasion
	packets, err := s.evasion.Apply(encrypted)
	if err != nil {
		s.log.Error("Evasion apply: %v", err)
		return
	}

	for _, p := range packets {
		delay := s.evasion.PreSendDelay()
		if delay > 0 {
			time.Sleep(delay)
		}

		var destIP net.IP
		if routeFlag == icmp.RouteViaRelay && relayIP != nil {
			destIP = relayIP
		} else {
			destIP = clientIP
		}

		// Use the server's local IP, send reply to client/relay
		localIP := net.ParseIP(s.cfg.Listen)
		if localIP == nil || localIP.Equal(net.IPv4zero) {
			localIP = getOutboundIP(destIP)
		}

		if err := s.socket.SendReply(localIP, destIP, p); err != nil {
			s.log.Error("Send response: %v", err)
		}
	}
}

func (s *Server) disableEchoReply() {
	cmd := exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
	if err := cmd.Run(); err != nil {
		s.log.Warn("Failed to disable echo reply: %v", err)
	} else {
		s.log.Info("Disabled kernel ICMP echo replies")
	}
}

func (s *Server) enableEchoReply() {
	cmd := exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
	if err := cmd.Run(); err != nil {
		s.log.Warn("Failed to re-enable echo reply: %v", err)
	}
}

func (s *Server) enableIPForwarding() {
	cmd := exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	if err := cmd.Run(); err != nil {
		s.log.Warn("Failed to enable IP forwarding: %v", err)
	} else {
		s.log.Info("Enabled IP forwarding")
	}
}
