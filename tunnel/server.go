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
	"strings"
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
	s.wg.Wait()
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
			select {
			case <-s.done:
				return
			default:
			}
			// Don't log timeouts to avoid spam, unless we want to debug headers
			if err.Error() != "receiving: resource temporarily unavailable" {
				s.log.Debug("Receive error: %v", err)
			}
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "bad file descriptor") {
				return
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
	ticker := time.NewTicker(200 * time.Millisecond) // Retransmission check
	sackTicker := time.NewTicker(1 * time.Second)    // SACK generation
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
					s.sendResponse(session.ClientAddr, session.ClientAddr, icmp.RouteDirect, nil, session.LastICMPID, session.LastICMPSeq, p)
				}
			})
		case <-sackTicker.C:
			s.sessionMgr.Iterate(func(session *icmp.Session) {
				if session.Authenticated {
					sackPkt := session.GenerateSACK().EncodePacket(session.ID)
					s.sendResponse(session.ClientAddr, session.ClientAddr, icmp.RouteDirect, nil, session.LastICMPID, session.LastICMPSeq, sackPkt)
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
			s.log.Debug("Packet from unauthenticated session %08x", pkt.SessionID)
			
			// Send AuthFail to trigger client reconnect
			failPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: pkt.SessionID,
				SeqNum:    0,
				Data:      icmp.EncodeControlMessage(icmp.ControlAuthFail, 0),
			}
			// We can't use session.RecordSent because we don't have a session.
			// Just send it directly.
			// Need to find which address to send to.
			// handlePacket has srcIP.
			s.sendResponse(clientIP, srcIP, routeFlag, relayIP, pkt.ICMPID, pkt.ICMPSeq, failPkt)
			return
		}

		// Reliability layer: sequencing and reordering
		var pkts []*icmp.TunnelPacket
		if session != nil {
			pkts = session.ProcessIncoming(pkt)
			if pkts == nil && session.IsDuplicate(pkt.SeqNum) {
				s.log.Debug("Received duplicate packet %d (type %d)", pkt.SeqNum, pkt.Type)
				
				if pkt.Type == icmp.TypeControl {
					s.log.Debug("Re-acknowledging duplicate control packet %d", pkt.SeqNum)
					s.handleControl(clientIP, srcIP, routeFlag, relayIP, pkt.ICMPID, pkt.ICMPSeq, session, pkt)
					return
				} else if pkt.Type == icmp.TypeData {
					// Duplicate Data packet: Re-send ACK so client stops retransmitting
					s.log.Debug("Re-acknowledging duplicate data packet %d", pkt.SeqNum)
					ackPkt := &icmp.TunnelPacket{
						Type:      icmp.TypeControl,
						SessionID: session.ID,
						SeqNum:    session.GetNextSeq(),
						Data:      icmp.EncodeControlMessage(icmp.ControlACK, pkt.SeqNum),
					}
					s.sendResponse(clientIP, srcIP, routeFlag, relayIP, pkt.ICMPID, pkt.ICMPSeq, ackPkt)
					return
				}
			}
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
		
		if session != nil {
			s.sessionMgr.TouchSession(pkt.SessionID)
		}
	}
}

func (s *Server) handleAuth(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, pkt *icmp.TunnelPacket) {
	token := string(pkt.Data)
	s.log.Info("Auth request from %s (session %08x)", clientIP, pkt.SessionID)

	var responseSubtype uint8
	session := s.sessionMgr.GetSession(pkt.SessionID)
	if s.authValidator.IsValid(token) {
		if session != nil && session.Authenticated && session.AuthToken == token {
			s.log.Debug("Re-authenticating existing session %08x", pkt.SessionID)
		} else {
			// Proactively cleanup old connections for this IP
			s.connMu.Lock()
			prefix := clientIP.String() + ":"
			for key, conn := range s.connections {
				if strings.HasPrefix(key, prefix) {
					s.log.Info("Cleaning up stale connection %s due to client restart", key)
					conn.Close()
					delete(s.connections, key)
				}
			}
			s.connMu.Unlock()

			session = s.sessionMgr.CreateSessionWithID(clientIP, pkt.SessionID)
			session.Authenticated = true
			session.AuthToken = token
			// Initialize NextRecvSeq to expect the next packet after this Auth packet
			session.NextRecvSeq = pkt.SeqNum + 1
			s.log.Info("Authentication successful for %s (session %08x), NextRecvSeq=%d", clientIP, pkt.SessionID, session.NextRecvSeq)
		}
		responseSubtype = icmp.ControlAuthOK
	} else {
		responseSubtype = icmp.ControlAuthFail
		s.log.Warn("Authentication failed for %s", clientIP)
	}

	var seqNum uint32
	if session != nil {
		seqNum = session.GetNextSeq()
	}

	responsePkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: pkt.SessionID,
		SeqNum:    seqNum,
		Data:      icmp.EncodeControlMessage(responseSubtype, 0),
	}

	if err := s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, responsePkt); err != nil {
		s.log.Error("Failed to send auth response: %v", err)
	} else if session != nil {
		session.RecordSent(responsePkt)
	}
}

func (s *Server) handleData(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, session *icmp.Session, pkt *icmp.TunnelPacket) {
	// Decode all stream entries from the aggregated payload
	entries, err := icmp.DecodeAllStreamData(pkt.Data)
	if err != nil {
		s.log.Error("Decode stream data: %v", err)
		return
	}

	for _, entry := range entries {
		session.Mu.RLock()
		stream, streamExists := session.Streams[entry.StreamID]
		session.Mu.RUnlock()

		if !streamExists {
			s.log.Warn("Data for unknown stream %d in session %08x", entry.StreamID, session.ID)
			continue
		}

		// Non-blocking push to avoid hanging the entire session if one stream is stuck
		select {
		case stream.DataChan <- entry.Data:
		default:
			s.log.Warn("Downlink buffer full for stream %d, dropping packet", entry.StreamID)
		}
	}

	// Immediate ACK to stop client retransmissions
	ackPkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: session.ID,
		SeqNum:    session.GetNextSeq(),
		Data:      icmp.EncodeControlMessage(icmp.ControlACK, pkt.SeqNum),
	}
	s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, ackPkt)
}

func (s *Server) handleControl(clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, icmpID, icmpSeq uint16, session *icmp.Session, pkt *icmp.TunnelPacket) {
	// Handle control messages
	subtype, value, err := icmp.DecodeControlMessage(pkt.Data)
	if err != nil {
		s.log.Error("Decode control: %v", err)
		return
	}
	
	streamID := uint16(value)
	s.log.Debug("Received Control packet: subtype=%d, value=%d from %s", subtype, value, clientIP)

	switch subtype {
	case icmp.ControlConnect:
		// Handle Connect asynchronously to avoid blocking the receiver loop
		go func() {
			req, err := icmp.DecodeConnectRequest(pkt.Data)
			if err != nil {
				s.log.Error("Decode connect request: %v", err)
				return
			}

			s.log.Info("Connect request: stream=%d proto=%s dest=%s from %s",
				req.StreamID, req.Protocol, req.Destination, clientIP)

			connKey := fmt.Sprintf("%s:%d", clientIP, req.StreamID)
			
			s.connMu.RLock()
			_, exists := s.connections[connKey]
			s.connMu.RUnlock()
			
			if exists {
				s.log.Debug("Connection for stream %s already exists, re-acknowledging", connKey)
				ackPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					SeqNum:    session.GetNextSeq(),
					Data:      icmp.EncodeControlMessage(icmp.ControlConnectACK, uint32(req.StreamID)),
				}
				session.RecordSent(ackPkt)
				s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, ackPkt)
				return
			}

			// Establish connection to destination
			var conn net.Conn
			var dErr error
			switch req.Protocol {
			case "tcp":
				conn, dErr = net.DialTimeout("tcp", req.Destination, 10*time.Second)
			case "udp":
				conn, dErr = net.DialTimeout("udp", req.Destination, 10*time.Second)
			default:
				s.log.Error("Unsupported protocol: %s", req.Protocol)
				return
			}

			if dErr != nil {
				// Retry with IPv6 formatting if it contains a colon and isn't bracketed
				dest := req.Destination
				if strings.Contains(dest, ":") && !strings.HasPrefix(dest, "[") {
					lastColon := strings.LastIndex(dest, ":")
					if lastColon != -1 {
						host := dest[:lastColon]
						port := dest[lastColon+1:]
						ipv6Dest := net.JoinHostPort(host, port)
						s.log.Debug("Retrying connection with IPv6 formatting: %s", ipv6Dest)
						conn, dErr = net.DialTimeout(req.Protocol, ipv6Dest, 10*time.Second)
					}
				}
			}

			if dErr != nil {
				s.log.Error("Connect to %s failed: %v", req.Destination, dErr)
				failPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					SeqNum:    session.GetNextSeq(),
					Data:      icmp.EncodeControlMessage(icmp.ControlConnectFail, uint32(req.StreamID)),
				}
				session.RecordSent(failPkt)
				s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, failPkt)
				return
			}

			s.connMu.Lock()
			s.connections[connKey] = conn
			s.connMu.Unlock()

			stream := session.AddStreamWithID(req.StreamID, req.Protocol, req.Destination)

			// Send connect ACK
			ackPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: session.ID,
				SeqNum:    session.GetNextSeq(),
				Data:      icmp.EncodeControlMessage(icmp.ControlConnectACK, uint32(req.StreamID)),
			}
			session.RecordSent(ackPkt)
			s.sendResponse(clientIP, srcIP, routeFlag, relayIP, icmpID, icmpSeq, ackPkt)
			s.log.Info("Stream %d established to %s", req.StreamID, req.Destination)

			// Start Uplink/Downlink loops
			s.wg.Add(2)
			go s.runUplink(session, stream, conn, connKey, req)
			go s.runDownlink(session, stream, conn, connKey, clientIP, srcIP, routeFlag, relayIP, req)
		}()

	case icmp.ControlACK:
		if session != nil {
			session.ProcessACK(value, nil)
		}
	case icmp.ControlSACK:
		if session != nil {
			sack, err := icmp.DecodeSACK(pkt.Data)
			if err == nil {
				session.ProcessACK(sack.AckedSeq, sack.Blocks)
			}
		}
	case icmp.ControlClose:
		connKey := fmt.Sprintf("%s:%d", clientIP, streamID)
		s.connMu.Lock()
		if conn, ok := s.connections[connKey]; ok {
			conn.Close()
			delete(s.connections, connKey)
			s.log.Info("Closed connection for stream %s", connKey)
		}
		s.connMu.Unlock()
		if session != nil {
			session.RemoveStream(streamID)
		}
	case icmp.ControlHeartbeat:
		// Heartbeat just touches session activity
	}

	// Send ACK for control messages that don't already send their own response.
	switch subtype {
	case icmp.ControlACK, icmp.ControlSACK, icmp.ControlHeartbeat:
		// These already have their own response or don't need ACK
	default:
		if session != nil {
			ackPkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: session.ID,
				SeqNum:    session.GetNextSeq(),
				Data:      icmp.EncodeControlMessage(icmp.ControlACK, pkt.SeqNum),
			}
			s.sendResponse(clientIP, srcIP, routeFlag, relayIP, pkt.ICMPID, pkt.ICMPSeq, ackPkt)
		}
	}
}

func (s *Server) runUplink(session *icmp.Session, stream *icmp.Stream, conn net.Conn, connKey string, req *icmp.ConnectRequest) {
	defer s.wg.Done()
	defer func() {
		conn.Close()
		s.connMu.Lock()
		delete(s.connections, connKey)
		s.connMu.Unlock()
		session.RemoveStream(req.StreamID)
		s.log.Debug("Uplink loop for stream %d to %s finished", req.StreamID, req.Destination)
	}()

	for {
		select {
		case data, ok := <-stream.DataChan:
			if !ok {
				return
			}
			s.log.Debug("Uplink: Writing %d bytes to %s for stream %d", len(data), req.Destination, req.StreamID)
			if _, err := conn.Write(data); err != nil {
				s.log.Error("Uplink: Write error to %s for stream %d: %v", req.Destination, req.StreamID, err)
				return
			}
		case <-s.done:
			return
		case <-stream.Done:
			return
		}
	}
}

func (s *Server) runDownlink(session *icmp.Session, stream *icmp.Stream, conn net.Conn, connKey string, clientIP, srcIP net.IP, routeFlag uint8, relayIP net.IP, req *icmp.ConnectRequest) {
	defer s.wg.Done()
	defer func() {
		conn.Close()
		s.connMu.Lock()
		delete(s.connections, connKey)
		s.connMu.Unlock()
	}()

	maxData := s.calculateMaxStreamData()
	buf := make([]byte, maxData)
	for {
		select {
		case <-s.done:
			return
		case <-stream.Done:
			return
		case <-session.Ctx.Done():
			return
		default:
		}

		// Backpressure: wait if the congestion window is full
		for {
			if session.GetInflightCount() < session.GetCWND() {
				break
			}
			select {
			case <-s.done:
				return
			case <-stream.Done:
				return
			case <-session.Ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
				// check again
			}
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				s.log.Debug("Downlink: EOF from %s for stream %d", req.Destination, req.StreamID)
				closePkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					SeqNum:    session.GetNextSeq(),
					Data:      icmp.EncodeControlMessage(icmp.ControlClose, uint32(req.StreamID)),
				}
				session.RecordSent(closePkt)
				s.sendResponse(clientIP, srcIP, routeFlag, relayIP, session.LastICMPID, session.LastICMPSeq, closePkt)
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.log.Error("Downlink: Read error from %s for stream %d: %v", req.Destination, req.StreamID, err)
			closePkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: session.ID,
				SeqNum:    session.GetNextSeq(),
				Data:      icmp.EncodeControlMessage(icmp.ControlClose, uint32(req.StreamID)),
			}
			session.RecordSent(closePkt)
			s.sendResponse(clientIP, srcIP, routeFlag, relayIP, session.LastICMPID, session.LastICMPSeq, closePkt)
			return
		}

		s.log.Debug("Downlink: Read %d bytes from %s for stream %d", n, req.Destination, req.StreamID)
		dataPkt := &icmp.TunnelPacket{
			Type:      icmp.TypeData,
			SessionID: session.ID,
			SeqNum:    session.GetNextSeq(),
			Data:      icmp.EncodeStreamData(req.StreamID, buf[:n]),
		}
		s.log.Debug("Downlink: Sending data packet seq=%d (%d bytes)", dataPkt.SeqNum, n)
		session.RecordSent(dataPkt)
		s.sendResponse(clientIP, srcIP, routeFlag, relayIP, session.LastICMPID, session.LastICMPSeq, dataPkt)
		
		// Micro-delay to prevent flooding
		time.Sleep(100 * time.Microsecond)
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

	// Subtract Tunnel header (11) and Stream Data header (4)
	room -= icmp.TunnelHeaderSize
	room -= icmp.StreamDataHeaderSize // Use the constant which is 4

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
