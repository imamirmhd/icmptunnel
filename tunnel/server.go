package tunnel

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imamirmhd/icmptunnel/auth"
	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/crypto"
	"github.com/imamirmhd/icmptunnel/evasion"
	"github.com/imamirmhd/icmptunnel/icmp"
	"github.com/imamirmhd/icmptunnel/logger"
)

// Server manages the server side of the ICMP tunnel.
type Server struct {
	cfg        *config.ServerConfig
	socket     *icmp.Socket
	encryptor  crypto.Encryptor
	evasion    *evasion.Manager
	sessionMgr *icmp.SessionManager
	authVal    *auth.Validator
	log        *logger.Logger
	localIP    net.IP

	sendQueue chan *sendItem

	// Multi-sender
	senderWorkers int
	senderWg      sync.WaitGroup

	done chan struct{}
	wg   sync.WaitGroup

	// Fragment buffers per session
	fragBufs   map[uint32]*evasion.FragmentBuffer
	fragBufsMu sync.Mutex

	// Stats
	statsTxPkts  uint64
	statsRxPkts  uint64
	statsTxBytes uint64
	statsRxBytes uint64
}

type sendItem struct {
	pkt    *icmp.TunnelPacket
	dstIP  net.IP
	srcIP  net.IP
	isReply bool
}

// NewServer creates a new tunnel server.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("server")

	readTimeout := config.ParseDuration(cfg.ICMP.ReadTimeout, 5*time.Second)
	writeTimeout := config.ParseDuration(cfg.ICMP.WriteTimeout, 5*time.Second)

	sock, err := icmp.NewSocket(cfg.ICMP.MaxPacketSize, cfg.ICMP.SocketBufMB, readTimeout, writeTimeout)
	if err != nil {
		return nil, fmt.Errorf("creating socket: %w", err)
	}

	if err := sock.Bind(cfg.Listen); err != nil {
		sock.Close()
		return nil, fmt.Errorf("binding: %w", err)
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
		log.Info("Encryption: %s", enc.Name())
	} else {
		enc = &crypto.NopEncryptor{}
	}

	evasionMgr := evasion.NewManager(cfg.Evasion)

	sessionTimeout := config.ParseDuration(cfg.Transport.SessionTimeout, 60*time.Second)
	sessionMgr := icmp.NewSessionManagerWithParams(sessionTimeout, cfg.Transport.WindowSize, cfg.Transport.WindowSize*4)

	authValidator := auth.NewValidator(cfg.AuthTokens)
	localIP := getLocalIP()

	senderWorkers := cfg.Transport.SenderWorkers
	if senderWorkers < 1 {
		senderWorkers = 4
	}

	return &Server{
		cfg:           cfg,
		socket:        sock,
		encryptor:     enc,
		evasion:       evasionMgr,
		sessionMgr:    sessionMgr,
		authVal:       authValidator,
		log:           log,
		localIP:       localIP,
		sendQueue:     make(chan *sendItem, 65536),
		senderWorkers: senderWorkers,
		done:          make(chan struct{}),
		fragBufs:      make(map[uint32]*evasion.FragmentBuffer),
	}, nil
}

// Start begins the tunnel server.
func (s *Server) Start() error {
	s.log.Info("Starting ICMP tunnel server on %s (workers=%d, cwnd=%d, compression=%s)",
		s.cfg.Listen, s.senderWorkers, s.cfg.Transport.WindowSize, s.cfg.Transport.Compression)

	// Start receiver goroutines
	for i := 0; i < 2; i++ {
		s.wg.Add(1)
		go s.recoverableRun(fmt.Sprintf("receiver-%d", i), s.receiveLoop)
	}

	// Start sender workers
	for i := 0; i < s.senderWorkers; i++ {
		s.senderWg.Add(1)
		s.wg.Add(1)
		workerID := i
		go s.recoverableRun(fmt.Sprintf("sender-%d", workerID), func() {
			defer s.senderWg.Done()
			s.senderWorker(workerID)
		})
	}

	// Start session maintenance
	s.wg.Add(1)
	go s.recoverableRun("maintenance", s.maintenanceLoop)

	// Start stats
	s.wg.Add(1)
	go s.recoverableRun("stats", s.statsLoop)

	s.log.Info("Server started")
	return nil
}

// Stop shuts down the tunnel server.
func (s *Server) Stop() {
	s.log.Info("Stopping server...")
	close(s.done)
	s.socket.Close()
	s.wg.Wait()
	s.log.Info("Server stopped")
}

// recoverableRun wraps goroutines with panic recovery.
func (s *Server) recoverableRun(name string, fn func()) {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("[PANIC] %s crashed: %v — restarting in 1s", name, r)
			time.Sleep(1 * time.Second)
			select {
			case <-s.done:
				return
			default:
				s.wg.Add(1)
				go s.recoverableRun(name, fn)
			}
		}
	}()
	fn()
}

// receiveLoop handles incoming ICMP packets.
func (s *Server) receiveLoop() {
	s.socket.SetReadDeadline(200 * time.Millisecond)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		srcIP, icmpType, id, seq, payload, rawBuf, err := s.socket.Receive()
		if err != nil {
			if rawBuf != nil {
				icmp.ReleaseBuffer(rawBuf)
			}
			continue
		}

		// Only process echo requests
		if icmpType != 8 {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		atomic.AddUint64(&s.statsRxPkts, 1)
		atomic.AddUint64(&s.statsRxBytes, uint64(len(payload)))

		data := payload
		if s.cfg.Encryption.Enabled {
			var decErr error
			data, decErr = s.encryptor.Decrypt(payload)
			if decErr != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		// Evasion removal
		if s.evasion.IsEnabled() {
			var evasErr error
			data, evasErr = s.evasion.RemoveInbound(data)
			if evasErr != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		tunnelPkt, decErr := icmp.DecodeTunnelPacket(data)
		icmp.ReleaseBuffer(rawBuf)
		if decErr != nil {
			continue
		}

		tunnelPkt.ICMPID = id
		tunnelPkt.ICMPSeq = seq

		// Handle spoof header
		clientIP := srcIP
		routeFlag := uint8(0)
		var relayIP net.IP

		if tunnelPkt.IsSpoofed() && len(tunnelPkt.Data) > icmp.SpoofHeaderSize {
			spoofHdr, innerData, err := icmp.ExtractSpoofHeader(tunnelPkt.Data)
			if err == nil {
				clientIP = spoofHdr.RealClientIP
				routeFlag = spoofHdr.RouteFlag
				relayIP = spoofHdr.RelayIP
				tunnelPkt.Data = innerData
			}
		}

		s.processPacket(clientIP, srcIP, tunnelPkt, id, seq, routeFlag, relayIP)
	}
}

// processPacket dispatches a decoded tunnel packet.
func (s *Server) processPacket(clientIP, srcIP net.IP, pkt *icmp.TunnelPacket, icmpID, icmpSeq uint16, routeFlag uint8, relayIP net.IP) {
	switch pkt.Type {
	case icmp.TypeAuth:
		s.handleAuth(clientIP, srcIP, pkt, icmpID, icmpSeq)
	case icmp.TypeControl:
		s.handleControl(clientIP, pkt, icmpID, icmpSeq, routeFlag, relayIP)
	case icmp.TypeData:
		s.handleData(clientIP, pkt, icmpID, icmpSeq, routeFlag, relayIP)
	case icmp.TypeDiag:
		s.handleDiag(clientIP, pkt, icmpID, icmpSeq)
	}
}

// handleAuth processes authentication packets.
func (s *Server) handleAuth(clientIP, srcIP net.IP, pkt *icmp.TunnelPacket, icmpID, icmpSeq uint16) {
	token := string(pkt.Data)
	s.log.Info("Auth attempt from %s (session %08x)", clientIP, pkt.SessionID)

	if !s.authVal.IsValid(token) {
		s.log.Warn("Auth failed from %s: invalid token", clientIP)
		s.sendControlReply(srcIP, pkt.SessionID, icmpID, icmpSeq, icmp.ControlAuthFail, 0)
		return
	}

	// Create/update session
	session := s.sessionMgr.CreateSessionWithID(clientIP, pkt.SessionID)
	session.Authenticated = true
	session.AuthToken = token
	session.LastICMPID = icmpID
	session.LastICMPSeq = icmpSeq

	s.log.Info("Auth success from %s, session %08x", clientIP, session.ID)
	s.sendControlReply(srcIP, session.ID, icmpID, icmpSeq, icmp.ControlAuthOK, session.ID)
}

// handleControl processes control messages.
func (s *Server) handleControl(clientIP net.IP, pkt *icmp.TunnelPacket, icmpID, icmpSeq uint16, routeFlag uint8, relayIP net.IP) {
	session := s.sessionMgr.GetSession(pkt.SessionID)
	if session == nil {
		return
	}
	if !session.Authenticated {
		return
	}

	s.sessionMgr.TouchSession(pkt.SessionID)
	session.AddICMPSlot(icmpID, icmpSeq)
	session.UpdateNATInfo(clientIP, routeFlag, relayIP)

	// Decompress if needed
	if pkt.Flags&icmp.FlagCompressed != 0 {
		decompressed, err := session.Decompress(pkt.Data)
		if err == nil {
			pkt.Data = decompressed
		}
	}

	if len(pkt.Data) < 1 {
		return
	}

	subtype := pkt.Data[0]
	switch subtype {
	case icmp.ControlHeartbeat:
		// Respond
		s.sendToClient(session, icmp.ControlHeartbeat, 0)

	case icmp.ControlACK:
		if len(pkt.Data) >= 5 {
			ackedSeq := binary.BigEndian.Uint32(pkt.Data[1:5])
			session.ProcessACK(ackedSeq, nil)
		}

	case icmp.ControlSACK:
		sack, err := icmp.DecodeSACK(pkt.Data)
		if err == nil {
			session.ProcessACK(sack.AckedSeq, sack.Blocks)
		}

	case icmp.ControlConnect:
		s.handleConnect(session, pkt.Data)

	case icmp.ControlClose:
		if len(pkt.Data) >= 5 {
			streamID := uint16(binary.BigEndian.Uint32(pkt.Data[1:5]))
			session.RemoveStream(streamID)
			s.log.Debug("Stream %d closed by client", streamID)
		} else if len(pkt.Data) >= 3 {
			streamID := binary.BigEndian.Uint16(pkt.Data[1:3])
			session.RemoveStream(streamID)
			s.log.Debug("Stream %d closed by client", streamID)
		}

	case icmp.ControlResume:
		s.handleResume(clientIP, pkt.Data, icmpID, icmpSeq)
	}
}

// handleConnect processes stream connect requests.
func (s *Server) handleConnect(session *icmp.Session, data []byte) {
	req, err := icmp.DecodeConnectRequest(data)
	if err != nil {
		s.log.Error("Invalid connect request: %v", err)
		return
	}

	s.log.Info("Stream %d connect: %s -> %s", req.StreamID, req.Protocol, req.Destination)

	stream := session.AddStreamWithID(req.StreamID, req.Protocol, req.Destination)

	// Start the downlink goroutine with crash guard
	go s.recoverableStreamRun(session, stream, req)
}

// recoverableStreamRun runs a downlink for a stream with panic recovery.
func (s *Server) recoverableStreamRun(session *icmp.Session, stream *icmp.Stream, req *icmp.ConnectRequest) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("[PANIC] Stream %d downlink crashed: %v", stream.ID, r)
			session.RemoveStream(stream.ID)
		}
	}()

	s.runDownlink(session, stream, req)
}

// runDownlink manages data flow from destination -> tunnel for a stream.
func (s *Server) runDownlink(session *icmp.Session, stream *icmp.Stream, req *icmp.ConnectRequest) {
	// Resolve and connect to destination
	var conn net.Conn
	var err error

	deadline := config.ParseDuration(s.cfg.Transport.DownlinkReadDeadline, 10*time.Millisecond)

	if req.Protocol == "udp" {
		conn, err = net.DialTimeout("udp", req.Destination, 10*time.Second)
	} else {
		conn, err = net.DialTimeout("tcp", req.Destination, 10*time.Second)
	}

	if err != nil {
		s.log.Error("Connect to %s failed: %v", req.Destination, err)
		// Send connect failure
		failData := make([]byte, 3)
		failData[0] = icmp.ControlConnectFail
		binary.BigEndian.PutUint16(failData[1:3], req.StreamID)
		s.sendToClient(session, icmp.ControlConnectFail, uint32(req.StreamID))
		session.RemoveStream(req.StreamID)
		return
	}
	defer conn.Close()

	// Send connect ACK
	s.sendToClient(session, icmp.ControlConnectACK, uint32(req.StreamID))
	stream.SetState(icmp.StreamStateOpen)

	// Uplink: tunnel -> destination
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("[PANIC] Stream %d uplink: %v", stream.ID, r)
			}
		}()

		for {
			select {
			case data, ok := <-stream.DataChan:
				if !ok {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn.Write(data); err != nil {
					return
				}
			case <-stream.Done:
				return
			case <-session.Ctx.Done():
				return
			}
		}
	}()

	// Downlink: destination -> tunnel (with aggregation)
	buf := make([]byte, s.cfg.ICMP.MaxPacketSize-200) // Leave room for headers
	for {
		select {
		case <-stream.Done:
			return
		case <-session.Ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(deadline))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err != io.EOF {
				s.log.Debug("Stream %d read error: %v", stream.ID, err)
			}
			// Send close
			s.sendToClient(session, icmp.ControlClose, uint32(req.StreamID))
			session.RemoveStream(req.StreamID)
			return
		}

		if n == 0 {
			continue
		}

		// Send data back through tunnel
		payload := icmp.EncodeStreamData(req.StreamID, buf[:n])
		pkt := &icmp.TunnelPacket{
			Type:      icmp.TypeData,
			SessionID: session.ID,
			SeqNum:    session.GetNextSeq(),
			Data:      payload,
			StreamIDs: []uint16{req.StreamID},
		}

		s.sendQueue <- &sendItem{
			pkt:     pkt,
			dstIP:   session.ClientAddr,
			srcIP:   s.localIP,
			isReply: true,
		}
	}
}

// handleResume processes session resume requests.
func (s *Server) handleResume(clientIP net.IP, data []byte, icmpID, icmpSeq uint16) {
	if len(data) < 13 {
		return
	}

	sessionID := binary.BigEndian.Uint32(data[1:5])
	// nextSeqSend := binary.BigEndian.Uint32(data[5:9])
	// nextSeqRecv := binary.BigEndian.Uint32(data[9:13])

	s.log.Info("Session resume request from %s for session %08x", clientIP, sessionID)

	// Check if we have a snapshot
	snap := s.sessionMgr.GetSnapshot(sessionID)
	if snap == nil {
		s.log.Warn("No snapshot for session %08x, requiring re-auth", sessionID)
		return
	}

	// Verify auth token matches
	session := s.sessionMgr.GetSession(sessionID)
	if session != nil {
		session.Mu.Lock()
		session.ClientAddr = clientIP
		session.LastActivity = time.Now()
		session.LastICMPID = icmpID
		session.LastICMPSeq = icmpSeq
		session.Mu.Unlock()
	} else {
		// Recreate session from snapshot
		session = s.sessionMgr.CreateSessionWithID(clientIP, sessionID)
		session.Authenticated = true
		session.AuthToken = snap.AuthToken
	}

	// Send resume ACK
	resumeACK := make([]byte, 1)
	resumeACK[0] = icmp.ControlResumeACK
	reply := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: sessionID,
		Data:      resumeACK,
	}
	s.sendQueue <- &sendItem{
		pkt:     reply,
		dstIP:   clientIP,
		srcIP:   s.localIP,
		isReply: true,
	}
	s.log.Info("Session %08x resumed for %s", sessionID, clientIP)
}

// handleData processes data packets from the client.
func (s *Server) handleData(clientIP net.IP, pkt *icmp.TunnelPacket, icmpID, icmpSeq uint16, routeFlag uint8, relayIP net.IP) {
	session := s.sessionMgr.GetSession(pkt.SessionID)
	if session == nil {
		return
	}
	if !session.Authenticated {
		return
	}

	s.sessionMgr.TouchSession(pkt.SessionID)
	session.AddICMPSlot(icmpID, icmpSeq)
	session.UpdateNATInfo(clientIP, routeFlag, relayIP)

	// Decompress if needed
	if pkt.Flags&icmp.FlagCompressed != 0 {
		decompressed, err := session.Decompress(pkt.Data)
		if err != nil {
			s.log.Error("Decompress failed: %v", err)
			return
		}
		pkt.Data = decompressed
	}

	// Process through reordering buffer
	ordered := session.ProcessIncoming(pkt)
	if ordered == nil {
		return
	}

	for _, orderedPkt := range ordered {
		// Send ACK
		s.sendToClient(session, icmp.ControlACK, orderedPkt.SeqNum)

		// Deliver to streams
		entries, err := icmp.DecodeAllStreamData(orderedPkt.Data)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			session.Mu.RLock()
			stream, ok := session.Streams[entry.StreamID]
			session.Mu.RUnlock()

			if !ok {
				continue
			}

			dataCopy := make([]byte, len(entry.Data))
			copy(dataCopy, entry.Data)

			select {
			case stream.DataChan <- dataCopy:
			default:
				s.log.Warn("Stream %d DataChan full, backpressure", entry.StreamID)
			}
		}
	}
}

// handleDiag processes diagnostic packets.
func (s *Server) handleDiag(clientIP net.IP, pkt *icmp.TunnelPacket, icmpID, icmpSeq uint16) {
	// Echo back for latency measurement
	reply := &icmp.TunnelPacket{
		Type:      icmp.TypeDiag,
		SessionID: pkt.SessionID,
		Data:      pkt.Data,
	}
	s.sendQueue <- &sendItem{
		pkt:     reply,
		dstIP:   clientIP,
		srcIP:   s.localIP,
		isReply: true,
	}
}

// sendToClient sends a control message to a session's client.
func (s *Server) sendToClient(session *icmp.Session, subtype uint8, value uint32) {
	data := icmp.EncodeControlMessage(subtype, value)
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: session.ID,
		Data:      data,
		Priority:  1,
	}
	s.sendQueue <- &sendItem{
		pkt:     pkt,
		dstIP:   session.ClientAddr,
		srcIP:   s.localIP,
		isReply: true,
	}
}

// sendControlReply sends a control message as a direct reply.
func (s *Server) sendControlReply(dstIP net.IP, sessionID uint32, icmpID, icmpSeq uint16, subtype uint8, value uint32) {
	data := icmp.EncodeControlMessage(subtype, value)
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: sessionID,
		Data:      data,
	}

	encoded := pkt.Encode()
	if s.cfg.Encryption.Enabled {
		var err error
		encoded, err = s.encryptor.Encrypt(encoded)
		if err != nil {
			s.log.Error("Encrypt reply failed: %v", err)
			return
		}
	}

	s.socket.SendReply(s.localIP, dstIP, icmpID, icmpSeq, encoded)
}

// senderWorker reads from the send queue and transmits packets.
func (s *Server) senderWorker(workerID int) {
	s.log.Debug("Sender worker %d started", workerID)

	for {
		select {
		case <-s.done:
			return
		case item := <-s.sendQueue:
			if item == nil || item.pkt == nil {
				continue
			}
			s.transmitPacket(item)
		}
	}
}

// transmitPacket sends a tunnel packet to a client.
func (s *Server) transmitPacket(item *sendItem) {
	pkt := item.pkt

	// CRC
	if s.cfg.Transport.EnableCRC {
		pkt.Flags |= icmp.FlagCRC
	}

	// Compression
	session := s.sessionMgr.GetSession(pkt.SessionID)
	if session != nil && s.cfg.Transport.Compression == "lz4" && len(pkt.Data) > 64 {
		compressed := session.Compress(pkt.Data)
		if len(compressed) < len(pkt.Data) {
			pkt.Data = compressed
			pkt.Flags |= icmp.FlagCompressed
		}
	}

	encoded := pkt.Encode()
	if s.cfg.Encryption.Enabled {
		var err error
		encoded, err = s.encryptor.Encrypt(encoded)
		if err != nil {
			s.log.Error("Encrypt failed: %v", err)
			return
		}
	}

	// Evasion
	if s.evasion.IsEnabled() {
		encoded = s.evasion.ApplyOutbound(encoded)
	}

	// Get ICMP slot from session
	var icmpID, icmpSeq uint16
	if session != nil {
		var err error
		icmpID, icmpSeq, err = session.GetICMPSlot(session.Ctx)
		if err != nil {
			// Generate our own
			icmpID = session.PushICMPID
			icmpSeq = session.GetNextICMPSeq()
		}
	}

	var sendErr error
	if item.isReply {
		sendErr = s.socket.SendReply(item.srcIP, item.dstIP, icmpID, icmpSeq, encoded)
	} else {
		sendErr = s.socket.Send(item.srcIP, item.dstIP, icmpID, icmpSeq, encoded)
	}

	if sendErr != nil {
		s.log.Error("Send to %s failed: %v", item.dstIP, sendErr)
		return
	}

	atomic.AddUint64(&s.statsTxPkts, 1)
	atomic.AddUint64(&s.statsTxBytes, uint64(len(encoded)))

	// Record inflight for data packets
	if session != nil && pkt.Type == icmp.TypeData {
		session.RecordSent(pkt)
	}
}

// maintenanceLoop handles retransmission, load shedding, and session SACK.
func (s *Server) maintenanceLoop() {
	retransTicker := time.NewTicker(50 * time.Millisecond)
	sackTicker := time.NewTicker(200 * time.Millisecond)
	defer retransTicker.Stop()
	defer sackTicker.Stop()

	for {
		select {
		case <-s.done:
			return

		case <-retransTicker.C:
			s.sessionMgr.Iterate(func(session *icmp.Session) {
				if !session.Authenticated {
					return
				}
				retrans := session.GetRetransmissions()
				for _, pkt := range retrans {
					s.sendQueue <- &sendItem{
						pkt:     pkt,
						dstIP:   session.ClientAddr,
						srcIP:   s.localIP,
						isReply: true,
					}
				}
			})

		case <-sackTicker.C:
			s.sessionMgr.Iterate(func(session *icmp.Session) {
				if !session.Authenticated {
					return
				}
				sack := session.GenerateSACK()
				sackPkt := sack.EncodePacket(session.ID)
				s.sendQueue <- &sendItem{
					pkt:     sackPkt,
					dstIP:   session.ClientAddr,
					srcIP:   s.localIP,
					isReply: true,
				}
			})
		}
	}
}

// statsLoop prints server stats periodically.
func (s *Server) statsLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			txPkts := atomic.LoadUint64(&s.statsTxPkts)
			rxPkts := atomic.LoadUint64(&s.statsRxPkts)
			sessions := s.sessionMgr.ActiveSessions()

			s.log.Info("[STATS] tx=%d rx=%d sessions=%d", txPkts, rxPkts, sessions)
		}
	}
}

// SetupTunInterface configures a TUN interface (if needed for full tunnel mode).
func SetupTunInterface(name, ip string) error {
	cmds := []struct {
		name string
		args []string
	}{
		{"ip", []string{"tuntap", "add", "dev", name, "mode", "tun"}},
		{"ip", []string{"addr", "add", ip, "dev", name}},
		{"ip", []string{"link", "set", "dev", name, "up"}},
	}

	for _, c := range cmds {
		cmd := exec.Command(c.name, c.args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			outStr := strings.TrimSpace(string(out))
			if !strings.Contains(outStr, "RTNETLINK answers: File exists") {
				return fmt.Errorf("running %s %v: %s (%w)", c.name, c.args, outStr, err)
			}
		}
	}
	return nil
}

// Wait blocks until the server is stopped.
func (s *Server) Wait() {
	<-s.done
}
