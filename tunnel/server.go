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

	// Start loops
	s.wg.Add(2)
	go s.receiveLoop()
	go s.retransmitLoop()

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

		srcIP, icmpType, icmpID, icmpSeq, rawPayload, err := s.socket.Receive()
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

		// If it's a reply (type 0), it must be from a relay with a spoof header.
		// If relaying is not enabled, we ignore type 0 packets.
		if icmpType == 0 && !s.cfg.Relay.Enabled {
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
				// If relay is enabled but no spoof header, only allow Type 8
				if icmpType == 0 {
					continue
				}
				realClientIP = srcIP
				tunnelPayload = rawPayload
			}
		} else {
			realClientIP = srcIP
			tunnelPayload = rawPayload
		}

		var tunnelPkt *icmp.TunnelPacket

		// Handle fragmentation if enabled
		var reassembledData []byte
		if s.cfg.Evasion.Fragmentation.Enabled {
			data, complete, fErr := fragBuf.Add(tunnelPayload)
			if fErr == nil {
				if !complete {
					continue // Waiting for more fragments
				}
				reassembledData = data
			} else {
				// Not a fragment or invalid, assume direct payload
				reassembledData = tunnelPayload
			}
		} else {
			reassembledData = tunnelPayload
		}

		// Apply other evasion reversal (Padding, Resizing)
		processedData, err := s.evasion.Unapply([][]byte{reassembledData})
		if err == nil {
			reassembledData = processedData
		} else {
			// If Unapply fails (e.g. bad padding), it might be an unencrypted ping.
			// Let it fall through to Decrypt, which will fail, then Ping check.
			s.log.Debug("Evasion Unapply failed from %s: %v", srcIP, err)
		}

		var decryptedPayload []byte
		decryptedPayload, err = s.encryptor.Decrypt(reassembledData)
		if err != nil {
			s.log.Debug("Decryption failed from %s: %v (data len: %d)", srcIP, err, len(reassembledData))
			// Decryption failed. This might be a standard ping.
			// Check if the original rawPayload or processedData matches a valid Auth Token prefix.
			if icmpType == 8 {
				isValid, _ := s.authValidator.IsValidPrefix(string(rawPayload))
				if isValid {
					s.log.Debug("Received valid authorized ping from %s", srcIP)
					localIP := s.getLocalIP(srcIP)
					if err := s.socket.SendReply(localIP, srcIP, icmpID, icmpSeq, rawPayload); err != nil {
						s.log.Error("Failed to send ping reply to %s: %v", srcIP, err)
					}
				}
			}
			continue
		}

		tunnelPkt, err = icmp.DecodeTunnelPacket(decryptedPayload)
		if err != nil {
			// Decoding failed. Check for Auth Token here too if it's an Echo Request.
			if icmpType == 8 {
				isValid, _ := s.authValidator.IsValidPrefix(string(rawPayload))
				if isValid {
					s.log.Debug("Received valid authorized ping from %s (decoded flow)", srcIP)
					localIP := s.getLocalIP(srcIP)
					if err := s.socket.SendReply(localIP, srcIP, icmpID, icmpSeq, rawPayload); err != nil {
						s.log.Error("Failed to send ping reply to %s: %v", srcIP, err)
					}
				} else {
					s.log.Debug("Decode tunnel packet failed: %v", err)
				}
			} else {
				s.log.Debug("Decode tunnel packet failed: %v", err)
			}
			continue
		}

		tunnelPkt.ICMPID = icmpID
		tunnelPkt.ICMPSeq = icmpSeq

		// Decompression
		if (tunnelPkt.Flags & icmp.FlagCompressed) != 0 {
			session := s.sessionMgr.GetSession(tunnelPkt.SessionID)
			if session != nil {
				decomp, err := session.Decompress(tunnelPkt.Data)
				if err == nil {
					tunnelPkt.Data = decomp
				}
			}
		}

		s.handlePacket(realClientIP, srcIP, routeFlag, relayIP, tunnelPkt)
	}
}

func (s *Server) retransmitLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	sackTicker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	defer sackTicker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sessionMgr.Iterate(func(session *icmp.Session) {
				retrans := session.GetRetransmissions()
				for _, p := range retrans {
					s.log.Debug("Retransmitting packet %d to %s", p.SeqNum, session.ClientAddr)
					s.sendResponse(session.ClientAddr, session.ClientAddr, icmp.RouteDirect, nil, 0, 0, p)
				}
			})
		case <-sackTicker.C:
			s.sessionMgr.Iterate(func(session *icmp.Session) {
				if !session.Authenticated {
					return
				}
				sack := session.GenerateSACK()
				if len(sack.Blocks) > 0 || sack.AckedSeq != session.NextSeqRecv - 1 {
					sackPkt := &icmp.TunnelPacket{
						Type:      icmp.TypeControl,
						SessionID: session.ID,
						SeqNum:    session.GetNextSeq(),
						Data:      icmp.EncodeSACK(sack),
					}
					s.sendResponse(session.ClientAddr, session.ClientAddr, icmp.RouteDirect, nil, 0, 0, sackPkt)
				}
			})
		}
	}
}

func (s *Server) handlePacket(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, pkt *icmp.TunnelPacket) {
	s.log.Debug("Handling packet type %d, session %08x, seq %d, icmp_id %d", pkt.Type, pkt.SessionID, pkt.SeqNum, pkt.ICMPID)
	switch pkt.Type {
	case icmp.TypeAuth, icmp.TypeDiag, icmp.TypeData, icmp.TypeControl:
		session := s.sessionMgr.GetSession(pkt.SessionID)
		if pkt.Type != icmp.TypeAuth && (session == nil || !session.Authenticated) {
			s.log.Warn("Packet from unauthenticated session %08x", pkt.SessionID)
			return
		}

		// Reliability layer: sequencing and reordering
		var pkts []*icmp.TunnelPacket
		if session != nil {
			pkts = session.ProcessIncoming(pkt)
		} else {
			pkts = []*icmp.TunnelPacket{pkt}
		}

		for _, p := range pkts {
			switch p.Type {
			case icmp.TypeAuth:
				s.handleAuth(clientIP, srcIP, routeFlag, relayIP, p.ICMPID, p.ICMPSeq, p)
			case icmp.TypeDiag:
				s.handleDiag(clientIP, srcIP, routeFlag, relayIP, p.ICMPID, p.ICMPSeq, p)
			case icmp.TypeData:
				s.handleData(clientIP, srcIP, routeFlag, relayIP, p.ICMPID, p.ICMPSeq, session, p)
			case icmp.TypeControl:
				s.handleControl(clientIP, srcIP, routeFlag, relayIP, p.ICMPID, p.ICMPSeq, session, p)
			}
		}

		// Handle SACKs specifically
		if pkt.Type == icmp.TypeControl {
			subtype, _, _ := icmp.DecodeControlMessage(pkt.Data)
			if subtype == icmp.ControlSACK {
				sack, err := icmp.DecodeSACK(pkt.Data)
				if err == nil {
					session.ProcessACK(sack.AckedSeq, sack.Blocks)
				}
			}
		}
	}
}

func (s *Server) handleAuth(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, pkt *icmp.TunnelPacket) {
	token := string(pkt.Data)
	s.log.Info("Auth request from %s (session %08x)", clientIP, pkt.SessionID)

	var responseSubtype uint8
	if s.authValidator.IsValid(token) {
		session := s.sessionMgr.CreateSessionWithID(clientIP, pkt.SessionID)
		session.Authenticated = true
		session.AuthToken = token
		session.MarkReceived(pkt.SeqNum)
		session.ProcessIncoming(pkt)
		responseSubtype = icmp.ControlAuthOK
		s.log.Info("Authentication successful for %s", clientIP)
	} else {
		responseSubtype = icmp.ControlAuthFail
		s.log.Warn("Authentication failed for %s", clientIP)
	}

	responsePkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: pkt.SessionID,
		SeqNum:    0, // Auth still uses 0 for now as it's the very first packet
		Data:      icmp.EncodeControlMessage(responseSubtype, 0),
	}

	if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, responsePkt); err != nil {
		s.log.Error("Failed to send auth response: %v", err)
	}
}

func (s *Server) handleData(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, session *icmp.Session, pkt *icmp.TunnelPacket) {
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

func (s *Server) handleControl(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, session *icmp.Session, pkt *icmp.TunnelPacket) {
	subtype, streamID, err := icmp.DecodeControlMessage(pkt.Data)
	if err != nil {
		s.log.Error("Decode control message: %v", err)
		return
	}

	switch subtype {
	case icmp.ControlConnect:
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
			failPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: session.ID,
				Data:      icmp.EncodeControlMessage(icmp.ControlConnectFail, req.StreamID),
			}
			if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, failPkt); err != nil {
				s.log.Error("Failed to send connect fail: %v", err)
			}
			return
		}

		connKey := fmt.Sprintf("%s:%d", clientIP, req.StreamID)
		s.connMu.Lock()
		s.connections[connKey] = conn
		s.connMu.Unlock()

		// Send connect ACK with streamID
		ackPkt := &icmp.TunnelPacket{
			Type:      icmp.TypeControl,
			SessionID: session.ID,
			SeqNum:    session.GetNextSeq(),
			Data:      icmp.EncodeControlMessage(icmp.ControlConnectACK, req.StreamID),
		}
		session.RecordSent(ackPkt)
		if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, ackPkt); err != nil {
			s.log.Error("Failed to send connect ACK: %v", err)
		}
		s.log.Info("Stream %d established to %s", req.StreamID, req.Destination)


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

		maxData := s.calculateMaxStreamData()
		buf := make([]byte, maxData)
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
				// Inform client about close
				closePkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					Data:      icmp.EncodeControlMessage(icmp.ControlClose, req.StreamID),
				}
				if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, 0, 0, closePkt); err != nil {
					s.log.Error("Failed to send close notification: %v", err)
				}
				return
			}

			streamData := icmp.EncodeStreamData(req.StreamID, buf[:n])
			
			// We skip the direct sendResponse and use the session's aggregation/reliable logic
			// But for now, let's keep it simple and just record it in session for retransmission
			dataPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeData,
				SessionID: session.ID,
				SeqNum:    session.GetNextSeq(),
				Data:      streamData,
			}

			session.RecordSent(dataPkt)
			if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, 0, 0, dataPkt); err != nil {
				s.log.Error("Send response to %s failed: %v", clientIP, err)
				return
			}
		}
	}()
	case icmp.ControlSACK:
		// Handled in handlePacket
	case icmp.ControlClose:
		connKey := fmt.Sprintf("%s:%d", clientIP, streamID)
		s.connMu.Lock()
		if conn, ok := s.connections[connKey]; ok {
			conn.Close()
			delete(s.connections, connKey)
			s.log.Info("Closed connection for stream %s", connKey)
		}
		s.connMu.Unlock()

	case icmp.ControlHeartbeat:
		// Just acknowledge activity

	case icmp.ControlACK:
		// This is an ACK for a packet we sent. No action needed on server side.
		// The client-side logic for pending ACKs would go here if this were client.go
	}

	// Always send ACK for control messages except ACKs themselves
	if subtype != icmp.ControlACK && session != nil {
		ackPkt := &icmp.TunnelPacket{
			Type:      icmp.TypeControl,
			SessionID: session.ID,
			SeqNum:    session.GetNextSeq(),
			Data:      icmp.EncodeControlMessage(icmp.ControlACK, pkt.SeqNum),
		}
		s.sendResponse(clientIP, srcIP, routeFlag, relayIP, pkt.ICMPID, pkt.ICMPSeq, ackPkt)
	}
}

func (s *Server) handleDiag(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, pkt *icmp.TunnelPacket) {
	// Echo back diagnostic data with server timestamp
	responsePkt := &icmp.TunnelPacket{
		Type:      icmp.TypeDiag,
		SessionID: pkt.SessionID,
		SeqNum:    pkt.SeqNum,
		Data:      pkt.Data,
	}
	if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, responsePkt); err != nil {
		s.log.Error("Failed to send diag response: %v", err)
	}
}

func (s *Server) calculateMaxStreamData() int {
	// Socket.Send check: 20 (IP) + 8 (ICMP) + len(payload) > s.maxPacketSize + 20
	// So len(payload) max is s.maxPacketSize - 8.
	room := s.cfg.ICMP.MaxPacketSize - 8

	// Subtract Evasion overhead
	room -= s.evasion.Overhead()

	// Subtract Encryption overhead
	room -= s.encryptor.Overhead()

	// Subtract Tunnel header (9) and Stream Data header (2)
	room -= icmp.TunnelHeaderSize
	room -= 2 // StreamDataHeaderSize

	if room < 64 {
		room = 64 // Minimum safety
	}
	s.log.Debug("Calculated max stream data size: %d", room)
	return room
}

func (s *Server) sendResponse(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, pkt *icmp.TunnelPacket) error {
	payload := pkt.Encode()

	encrypted, err := s.encryptor.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Apply evasion
	packets, err := s.evasion.Apply(encrypted)
	if err != nil {
		return fmt.Errorf("evasion: %w", err)
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
		localIP := s.getLocalIP(destIP)
		if localIP == nil || localIP.IsUnspecified() {
			return fmt.Errorf("could not find local IP")
		}

		if err := s.socket.SendReply(localIP, destIP, icmpID, icmpSeq, p); err != nil {
			return fmt.Errorf("socket send: %w", err)
		}
	}
	return nil
}

func (s *Server) getLocalIP(destIP net.IP) net.IP {
	localIP := net.ParseIP(s.cfg.Listen)
	if localIP == nil || localIP.Equal(net.IPv4zero) || localIP.IsUnspecified() {
		localIP = getOutboundIP(destIP)
	}
	return localIP
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
