// Package tunnel implements the core client and server tunnel logic.
package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/crypto"
	"github.com/imamirmhd/icmptunnel/evasion"
	"github.com/imamirmhd/icmptunnel/icmp"
	"github.com/imamirmhd/icmptunnel/logger"
	"github.com/imamirmhd/icmptunnel/proxy"
)

// Client manages the client side of the ICMP tunnel.
type Client struct {
	cfg        *config.ClientConfig
	socket     *icmp.Socket
	encryptor  crypto.Encryptor
	evasion    *evasion.Manager
	session    *icmp.Session
	log        *logger.Logger
	serverIP   net.IP
	localIP    net.IP
	sendQueue  chan *icmp.TunnelPacket

	// Multi-sender support
	senderWorkers int
	senderWg      sync.WaitGroup

	// Connection state
	connected    int32 // atomic
	reconnecting int32 // atomic
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Stats
	statsTxPkts     uint64
	statsRxPkts     uint64
	statsTxBytes    uint64
	statsRxBytes    uint64
	statsReconnects uint64
	statsStartTime  time.Time

	// Fragment buffer
	fragBuf *evasion.FragmentBuffer

	// Spoof config
	spoofEnabled bool
	relayIP      net.IP
	spoofSrcIP   net.IP

	// Replay buffer for reconnect
	replayBuf    []*icmp.TunnelPacket
	replayMu     sync.Mutex
	replayMaxLen int

	// Aggregation
	aggregationDelay time.Duration
}

// NewClient creates a new tunnel client.
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("client")

	serverIP := net.ParseIP(cfg.ServerAddr)
	if serverIP == nil {
		ips, err := net.LookupIP(cfg.ServerAddr)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolving server address %s: %w", cfg.ServerAddr, err)
		}
		serverIP = ips[0].To4()
	}

	readTimeout := config.ParseDuration(cfg.ICMP.ReadTimeout, 5*time.Second)
	writeTimeout := config.ParseDuration(cfg.ICMP.WriteTimeout, 5*time.Second)

	sock, err := icmp.NewSocket(cfg.ICMP.MaxPacketSize, cfg.ICMP.SocketBufMB, readTimeout, writeTimeout)
	if err != nil {
		return nil, fmt.Errorf("creating socket: %w", err)
	}

	// Bind to 0.0.0.0
	if err := sock.Bind("0.0.0.0"); err != nil {
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
		log.Info("Encryption: %s", enc.Name())
	} else {
		enc = &crypto.NopEncryptor{}
	}

	evasionMgr := evasion.NewManager(cfg.Evasion)

	ctx, cancel := context.WithCancel(context.Background())
	localIP := getLocalIP()

	aggDelay := config.ParseDuration(cfg.Transport.AggregationDelay, 500*time.Microsecond)
	senderWorkers := cfg.Transport.SenderWorkers
	if senderWorkers < 1 {
		senderWorkers = 4
	}

	replayMax := cfg.Recovery.ReplayBufferSize
	if replayMax == 0 {
		replayMax = 65536
	}

	c := &Client{
		cfg:              cfg,
		socket:           sock,
		encryptor:        enc,
		evasion:          evasionMgr,
		log:              log,
		serverIP:         serverIP,
		localIP:          localIP,
		sendQueue:        make(chan *icmp.TunnelPacket, 65536),
		senderWorkers:    senderWorkers,
		ctx:              ctx,
		cancel:           cancel,
		fragBuf:          evasion.NewFragmentBuffer(),
		aggregationDelay: aggDelay,
		replayMaxLen:     replayMax,
		statsStartTime:   time.Now(),
	}

	if cfg.Spoof.Enabled {
		c.spoofEnabled = true
		c.relayIP = net.ParseIP(cfg.Spoof.RelayAddr)
		c.spoofSrcIP = net.ParseIP(cfg.Spoof.SourceIP)
		log.Info("Spoofing enabled: relay=%s src=%s", c.relayIP, c.spoofSrcIP)
	}

	return c, nil
}

// Start begins the tunnel client.
func (c *Client) Start() error {
	c.log.Info("Starting ICMP tunnel client -> %s (workers=%d, cwnd=%d, compression=%s)",
		c.serverIP, c.senderWorkers, c.cfg.Transport.WindowSize, c.cfg.Transport.Compression)

	if err := c.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	atomic.StoreInt32(&c.connected, 1)

	// Start receiver
	c.wg.Add(1)
	go c.recoverableRun("receiver", c.receiveLoop)

	// Start multiple sender workers
	for i := 0; i < c.senderWorkers; i++ {
		c.senderWg.Add(1)
		c.wg.Add(1)
		workerID := i
		go c.recoverableRun(fmt.Sprintf("sender-%d", workerID), func() {
			defer c.senderWg.Done()
			c.senderWorker(workerID)
		})
	}

	// Start retransmission checker
	c.wg.Add(1)
	go c.recoverableRun("retransmit", c.retransmitLoop)

	// Start heartbeat
	c.wg.Add(1)
	go c.recoverableRun("heartbeat", c.heartbeatLoop)

	// Start SACK sender
	c.wg.Add(1)
	go c.recoverableRun("sack", c.sackLoop)

	// Start stats printer
	c.wg.Add(1)
	go c.recoverableRun("stats", c.statsLoop)

	// Start proxies
	for _, s5cfg := range c.cfg.Socks5 {
		if err := c.startSocks5(s5cfg); err != nil {
			c.log.Error("Failed to start SOCKS5 on %s: %v", s5cfg.Listen, err)
		}
	}

	for _, fwdCfg := range c.cfg.Forwards {
		if err := c.startForward(fwdCfg); err != nil {
			c.log.Error("Failed to start forward %s: %v", fwdCfg.Listen, err)
		}
	}

	c.log.Info("Client started successfully")
	return nil
}

// Stop shuts down the tunnel client.
func (c *Client) Stop() {
	c.log.Info("Stopping client...")
	c.cancel()
	c.socket.Close()
	c.wg.Wait()
	c.log.Info("Client stopped")
}

// recoverableRun wraps a function with panic recovery (crash guard).
func (c *Client) recoverableRun(name string, fn func()) {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("[PANIC] %s crashed: %v — restarting in 1s", name, r)
			time.Sleep(1 * time.Second)
			select {
			case <-c.ctx.Done():
				return
			default:
				c.wg.Add(1)
				go c.recoverableRun(name, fn)
			}
		}
	}()
	fn()
}

// authenticate performs the authentication handshake.
func (c *Client) authenticate() error {
	c.log.Info("Authenticating with server %s...", c.serverIP)

	sessionTimeout := config.ParseDuration(c.cfg.Transport.SessionTimeout, 60*time.Second)
	sessionMgr := icmp.NewSessionManagerWithParams(sessionTimeout, c.cfg.Transport.WindowSize, c.cfg.Transport.WindowSize*4)

	session := sessionMgr.CreateSession(c.localIP)
	session.AuthToken = c.cfg.AuthToken
	c.session = session

	// Send auth packet
	authData := []byte(c.cfg.AuthToken)
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeAuth,
		Flags:     icmp.FlagAuth,
		SessionID: session.ID,
		Data:      authData,
	}
	if c.cfg.Transport.EnableCRC {
		pkt.Flags |= icmp.FlagCRC
	}

	seq := session.GetNextICMPSeq()
	encoded := pkt.Encode()

	if c.cfg.Encryption.Enabled {
		var err error
		encoded, err = c.encryptor.Encrypt(encoded)
		if err != nil {
			return fmt.Errorf("encrypting auth: %w", err)
		}
	}

	if err := c.socket.Send(c.localIP, c.serverIP, session.OutboundICMPID, seq, encoded); err != nil {
		return fmt.Errorf("sending auth: %w", err)
	}

	// Wait for auth response with timeout
	deadline := time.Now().Add(10 * time.Second)
	c.socket.SetReadDeadline(2 * time.Second)

	for time.Now().Before(deadline) {
		srcIP, _, _, _, payload, rawBuf, err := c.socket.Receive()
		if err != nil {
			continue
		}

		if !srcIP.Equal(c.serverIP) {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		data := payload
		if c.cfg.Encryption.Enabled {
			data, err = c.encryptor.Decrypt(payload)
			if err != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		tunnelPkt, err := icmp.DecodeTunnelPacket(data)
		icmp.ReleaseBuffer(rawBuf)
		if err != nil {
			continue
		}

		if tunnelPkt.Type == icmp.TypeControl && len(tunnelPkt.Data) > 0 {
			subtype := tunnelPkt.Data[0]
			if subtype == icmp.ControlAuthOK {
				session.Authenticated = true
				if len(tunnelPkt.Data) >= 5 {
					session.ID = binary.BigEndian.Uint32(tunnelPkt.Data[1:5])
				}
				c.log.Info("Authenticated! Session ID: %08x", session.ID)
				c.socket.SetReadDeadline(config.ParseDuration(c.cfg.ICMP.ReadTimeout, 5*time.Second))
				return nil
			} else if subtype == icmp.ControlAuthFail {
				return fmt.Errorf("server rejected authentication")
			}
		}
	}

	return fmt.Errorf("auth timeout — no response from server")
}

// receiveLoop continuously receives ICMP packets from the server.
func (c *Client) receiveLoop() {
	c.log.Debug("Receive loop started")
	c.socket.SetReadDeadline(200 * time.Millisecond)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		srcIP, _, id, seq, payload, rawBuf, err := c.socket.Receive()
		if err != nil {
			if rawBuf != nil {
				icmp.ReleaseBuffer(rawBuf)
			}
			continue
		}

		if !srcIP.Equal(c.serverIP) {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		// Store ICMP slot for server response pairing
		c.session.AddICMPSlot(id, seq)

		data := payload
		if c.cfg.Encryption.Enabled {
			var decErr error
			data, decErr = c.encryptor.Decrypt(payload)
			if decErr != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		// Evasion removal
		if c.evasion.IsEnabled() {
			var evasErr error
			data, evasErr = c.evasion.RemoveInbound(data)
			if evasErr != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		// Handle defragmentation
		if c.evasion.IsFragmentEnabled() {
			reassembled, complete, fragErr := c.fragBuf.Add(data)
			if fragErr != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
			if !complete {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
			data = reassembled
		}

		tunnelPkt, decErr := icmp.DecodeTunnelPacket(data)
		icmp.ReleaseBuffer(rawBuf)
		if decErr != nil {
			continue
		}

		tunnelPkt.ICMPID = id
		tunnelPkt.ICMPSeq = seq

		atomic.AddUint64(&c.statsRxPkts, 1)
		atomic.AddUint64(&c.statsRxBytes, uint64(len(tunnelPkt.Data)))

		c.processIncoming(tunnelPkt)
	}
}

// processIncoming handles a decoded tunnel packet.
func (c *Client) processIncoming(pkt *icmp.TunnelPacket) {
	// Decompress if needed
	if pkt.Flags&icmp.FlagCompressed != 0 && c.session != nil {
		decompressed, err := c.session.Decompress(pkt.Data)
		if err != nil {
			c.log.Error("Decompress failed: %v", err)
			return
		}
		pkt.Data = decompressed
	}

	switch pkt.Type {
	case icmp.TypeControl:
		c.handleControl(pkt)
	case icmp.TypeData:
		c.handleData(pkt)
	case icmp.TypeDiag:
		c.handleDiag(pkt)
	}
}

// handleControl processes control messages.
func (c *Client) handleControl(pkt *icmp.TunnelPacket) {
	if len(pkt.Data) < 1 {
		return
	}

	subtype := pkt.Data[0]
	switch subtype {
	case icmp.ControlHeartbeat:
		// Respond with heartbeat
		c.sendControl(icmp.ControlHeartbeat, 0)

	case icmp.ControlACK:
		if len(pkt.Data) >= 5 {
			ackedSeq := binary.BigEndian.Uint32(pkt.Data[1:5])
			acked := c.session.ProcessACK(ackedSeq, nil)
			_ = acked

			// Check for fast retransmit
			fastRetrans := c.session.FastRetransmit(ackedSeq)
			for _, rpkt := range fastRetrans {
				c.sendQueue <- rpkt
			}
		}

	case icmp.ControlSACK:
		sack, err := icmp.DecodeSACK(pkt.Data)
		if err != nil {
			return
		}
		c.session.ProcessACK(sack.AckedSeq, sack.Blocks)

	case icmp.ControlConnectACK:
		if len(pkt.Data) >= 3 {
			streamID := binary.BigEndian.Uint16(pkt.Data[1:3])
			c.session.Mu.Lock()
			if stream, ok := c.session.Streams[streamID]; ok {
				stream.SetState(icmp.StreamStateOpen)
			}
			c.session.Mu.Unlock()
			c.log.Debug("Stream %d connected", streamID)
		}

	case icmp.ControlConnectFail:
		if len(pkt.Data) >= 3 {
			streamID := binary.BigEndian.Uint16(pkt.Data[1:3])
			c.session.RemoveStream(streamID)
			c.log.Warn("Stream %d connect failed", streamID)
		}

	case icmp.ControlClose:
		if len(pkt.Data) >= 3 {
			streamID := binary.BigEndian.Uint16(pkt.Data[1:3])
			c.session.RemoveStream(streamID)
		}

	case icmp.ControlResumeACK:
		c.log.Info("Session resume acknowledged by server")
		atomic.StoreInt32(&c.connected, 1)
		atomic.StoreInt32(&c.reconnecting, 0)
	}
}

// handleData processes data packets.
func (c *Client) handleData(pkt *icmp.TunnelPacket) {
	if c.session == nil || len(pkt.Data) == 0 {
		return
	}

	// Process through reordering buffer
	ordered := c.session.ProcessIncoming(pkt)
	if ordered == nil {
		return
	}

	for _, orderedPkt := range ordered {
		// Send cumulative ACK
		c.sendControl(icmp.ControlACK, orderedPkt.SeqNum)

		// Decode and deliver stream data
		entries, err := icmp.DecodeAllStreamData(orderedPkt.Data)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			c.session.Mu.RLock()
			stream, ok := c.session.Streams[entry.StreamID]
			c.session.Mu.RUnlock()

			if !ok {
				continue
			}

			// Non-blocking send with backpressure
			select {
			case stream.DataChan <- entry.Data:
				atomic.AddUint64(&stream.RxBytes, uint64(len(entry.Data)))
			default:
				c.log.Warn("Stream %d DataChan full, dropping %d bytes (backpressure)", entry.StreamID, len(entry.Data))
			}
		}
	}
}

// handleDiag handles diagnostic packets.
func (c *Client) handleDiag(pkt *icmp.TunnelPacket) {
	// Echo back for latency measurement
	c.sendQueue <- &icmp.TunnelPacket{
		Type:      icmp.TypeDiag,
		SessionID: c.session.ID,
		Data:      pkt.Data,
	}
}

// senderWorker reads from the send queue and transmits packets.
func (c *Client) senderWorker(workerID int) {
	c.log.Debug("Sender worker %d started", workerID)

	// Aggregation buffer
	aggBuf := make([]byte, 0, c.cfg.ICMP.MaxPacketSize)
	aggTimer := time.NewTimer(c.aggregationDelay)
	aggTimer.Stop()
	var aggPkts []*icmp.TunnelPacket

	flushAgg := func() {
		if len(aggPkts) == 0 {
			return
		}
		// Send aggregated packet
		for _, pkt := range aggPkts {
			c.transmitPacket(pkt)
		}
		aggPkts = aggPkts[:0]
		aggBuf = aggBuf[:0]
		aggTimer.Stop()
	}

	for {
		select {
		case <-c.ctx.Done():
			flushAgg()
			return

		case pkt := <-c.sendQueue:
			if pkt == nil {
				continue
			}
			// Control packets bypass aggregation
			if pkt.Type == icmp.TypeControl {
				pkt.Priority = 1
				c.transmitPacket(pkt)
				continue
			}

			aggPkts = append(aggPkts, pkt)
			aggBuf = append(aggBuf, pkt.Data...)

			if len(aggBuf) >= c.cfg.ICMP.MaxPacketSize-100 || len(aggPkts) >= 16 {
				flushAgg()
			} else if len(aggPkts) == 1 {
				aggTimer.Reset(c.aggregationDelay)
			}

		case <-aggTimer.C:
			flushAgg()
		}
	}
}

// transmitPacket sends a single tunnel packet over ICMP.
func (c *Client) transmitPacket(pkt *icmp.TunnelPacket) {
	if c.session == nil {
		return
	}

	// Wait for congestion window capacity (non-blocking for control)
	if pkt.Type == icmp.TypeData {
		waitCtx, waitCancel := context.WithTimeout(c.ctx, 5*time.Second)
		if err := c.session.WaitSendCapacity(waitCtx); err != nil {
			waitCancel()
			return
		}
		waitCancel()
	}

	pkt.SessionID = c.session.ID
	if pkt.SeqNum == 0 && pkt.Type == icmp.TypeData {
		pkt.SeqNum = c.session.GetNextSeq()
	}

	// CRC
	if c.cfg.Transport.EnableCRC {
		pkt.Flags |= icmp.FlagCRC
	}

	// Compression
	if c.cfg.Transport.Compression == "lz4" && len(pkt.Data) > 64 {
		compressed := c.session.Compress(pkt.Data)
		if len(compressed) < len(pkt.Data) {
			pkt.Data = compressed
			pkt.Flags |= icmp.FlagCompressed
		}
	}

	// Encryption
	encoded := pkt.Encode()
	if c.cfg.Encryption.Enabled {
		var err error
		encoded, err = c.encryptor.Encrypt(encoded)
		if err != nil {
			c.log.Error("Encrypt failed: %v", err)
			return
		}
		pkt.Flags |= icmp.FlagEncrypted
	}

	// Evasion
	if c.evasion.IsEnabled() {
		encoded = c.evasion.ApplyOutbound(encoded)
	}

	// Fragment if needed
	var fragments [][]byte
	if c.evasion.IsFragmentEnabled() {
		fragments = c.evasion.Fragment(encoded)
	} else {
		fragments = [][]byte{encoded}
	}

	// Determine destination
	dstIP := c.serverIP
	srcIP := c.localIP
	if c.spoofEnabled && c.relayIP != nil {
		dstIP = c.relayIP
		srcIP = c.spoofSrcIP
	}

	for _, frag := range fragments {
		seq := c.session.GetNextICMPSeq()
		if err := c.socket.Send(srcIP, dstIP, c.session.OutboundICMPID, seq, frag); err != nil {
			c.log.Error("Send failed: %v", err)
			continue
		}
		atomic.AddUint64(&c.statsTxPkts, 1)
		atomic.AddUint64(&c.statsTxBytes, uint64(len(frag)))
	}

	// Record inflight for retransmission
	if pkt.Type == icmp.TypeData {
		c.session.RecordSent(pkt)
	}

	// Evasion jitter
	c.evasion.ApplyJitter()
}

// sendControl sends a control message.
func (c *Client) sendControl(subtype uint8, value uint32) {
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: c.session.ID,
		Data:      icmp.EncodeControlMessage(subtype, value),
		Priority:  1,
	}
	select {
	case c.sendQueue <- pkt:
	default:
		// Queue full, try direct send for critical control messages
		c.transmitPacket(pkt)
	}
}

// retransmitLoop checks for timed-out packets and retransmits them.
func (c *Client) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if c.session == nil {
				continue
			}
			retrans := c.session.GetRetransmissions()
			for _, pkt := range retrans {
				select {
				case c.sendQueue <- pkt:
				default:
					c.log.Warn("Retransmit queue full, dropping")
				}
			}

			// Load shedding check
			if c.session.ShouldShed() {
				lowest := c.session.GetLowestPriorityStream()
				if lowest > 0 {
					c.log.Warn("Load shedding: dropping stream %d", lowest)
					c.session.RemoveStream(lowest)
				}
			}
		}
	}
}

// heartbeatLoop sends periodic heartbeats to keep the session alive.
func (c *Client) heartbeatLoop() {
	interval := config.ParseDuration(c.cfg.Transport.HeartbeatInterval, 5*time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	missedBeats := 0

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&c.connected) == 0 {
				missedBeats++
				if missedBeats > 3 && atomic.CompareAndSwapInt32(&c.reconnecting, 0, 1) {
					go c.reconnect()
				}
				continue
			}
			c.sendControl(icmp.ControlHeartbeat, 0)
			missedBeats = 0
		}
	}
}

// sackLoop sends periodic SACKs to the server.
func (c *Client) sackLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if c.session == nil {
				continue
			}
			sack := c.session.GenerateSACK()
			sackPkt := sack.EncodePacket(c.session.ID)
			c.sendQueue <- sackPkt
		}
	}
}

// reconnect attempts to reconnect to the server.
func (c *Client) reconnect() {
	defer atomic.StoreInt32(&c.reconnecting, 0)

	c.log.Info("Attempting reconnect...")
	atomic.AddUint64(&c.statsReconnects, 1)

	// Save session state for resume
	snapshot := c.session.TakeSnapshot()

	baseDelay := config.ParseDuration(c.cfg.Recovery.ReconnectDelay, 100*time.Millisecond)
	maxDelay := config.ParseDuration(c.cfg.Recovery.MaxReconnectDelay, 30*time.Second)
	maxAttempts := c.cfg.Recovery.MaxReconnects
	if maxAttempts == 0 {
		maxAttempts = 100
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Try session resume first (single-RTT reconnect)
		if snapshot != nil {
			if err := c.trySessionResume(snapshot); err == nil {
				c.log.Info("Session resumed successfully (attempt %d)", attempt+1)
				atomic.StoreInt32(&c.connected, 1)
				return
			}
		}

		// Fall back to full re-auth
		if err := c.authenticate(); err == nil {
			c.log.Info("Reconnected via re-auth (attempt %d)", attempt+1)
			atomic.StoreInt32(&c.connected, 1)

			// Replay buffered packets
			c.replayMu.Lock()
			for _, rpkt := range c.replayBuf {
				select {
				case c.sendQueue <- rpkt:
				default:
				}
			}
			c.replayBuf = c.replayBuf[:0]
			c.replayMu.Unlock()
			return
		}

		// Exponential backoff with jitter
		delay := baseDelay * time.Duration(1<<uint(attempt))
		if delay > maxDelay {
			delay = maxDelay
		}
		jitter := time.Duration(rand.Int63n(int64(delay / 4)))
		time.Sleep(delay + jitter)
	}

	c.log.Error("Failed to reconnect after %d attempts", maxAttempts)
}

// trySessionResume attempts a single-RTT session resume.
func (c *Client) trySessionResume(snapshot *icmp.SessionSnapshot) error {
	resumeData := make([]byte, 13)
	resumeData[0] = icmp.ControlResume
	binary.BigEndian.PutUint32(resumeData[1:5], snapshot.SessionID)
	binary.BigEndian.PutUint32(resumeData[5:9], snapshot.NextSeqSend)
	binary.BigEndian.PutUint32(resumeData[9:13], snapshot.NextSeqRecv)

	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: snapshot.SessionID,
		Data:      resumeData,
		Priority:  2,
	}

	seq := c.session.GetNextICMPSeq()
	encoded := pkt.Encode()

	if c.cfg.Encryption.Enabled {
		var err error
		encoded, err = c.encryptor.Encrypt(encoded)
		if err != nil {
			return err
		}
	}

	if err := c.socket.Send(c.localIP, c.serverIP, c.session.OutboundICMPID, seq, encoded); err != nil {
		return err
	}

	// Wait for resume ACK
	deadline := time.Now().Add(3 * time.Second)
	c.socket.SetReadDeadline(1 * time.Second)
	defer c.socket.SetReadDeadline(config.ParseDuration(c.cfg.ICMP.ReadTimeout, 5*time.Second))

	for time.Now().Before(deadline) {
		srcIP, _, _, _, payload, rawBuf, err := c.socket.Receive()
		if err != nil {
			continue
		}

		if !srcIP.Equal(c.serverIP) {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		data := payload
		if c.cfg.Encryption.Enabled {
			data, err = c.encryptor.Decrypt(payload)
			if err != nil {
				icmp.ReleaseBuffer(rawBuf)
				continue
			}
		}

		tp, err := icmp.DecodeTunnelPacket(data)
		icmp.ReleaseBuffer(rawBuf)
		if err != nil {
			continue
		}

		if tp.Type == icmp.TypeControl && len(tp.Data) > 0 && tp.Data[0] == icmp.ControlResumeACK {
			return nil
		}
	}

	return fmt.Errorf("resume timeout")
}

// statsLoop prints real-time stats periodically.
func (c *Client) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastTx, lastRx uint64

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			txPkts := atomic.LoadUint64(&c.statsTxPkts)
			rxPkts := atomic.LoadUint64(&c.statsRxPkts)
			txBytes := atomic.LoadUint64(&c.statsTxBytes)
			rxBytes := atomic.LoadUint64(&c.statsRxBytes)
			reconnects := atomic.LoadUint64(&c.statsReconnects)

			txRate := float64(txBytes-lastTx) / 5.0
			rxRate := float64(rxBytes-lastRx) / 5.0
			lastTx = txBytes
			lastRx = rxBytes

			stats := c.session.GetStats()

			c.log.Info("[STATS] tx=%d rx=%d txRate=%.1fKB/s rxRate=%.1fKB/s cwnd=%d inflight=%d rtt=%v retrans=%d reconnects=%d streams=%d",
				txPkts, rxPkts,
				txRate/1024, rxRate/1024,
				stats.CWND, stats.Inflight,
				stats.RTT, stats.Retransmits,
				reconnects, stats.Streams)
		}
	}
}

// ---- Proxy Integration ----

func (c *Client) startSocks5(s5cfg config.Socks5Config) error {
	socks, err := proxy.NewSOCKS5Server(s5cfg.Listen, s5cfg.Username, s5cfg.Password)
	if err != nil {
		return err
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		socks.Serve(func(destination string) (chan<- []byte, <-chan []byte, error) {
			return c.openStream("tcp", destination)
		})
	}()

	c.log.Info("SOCKS5 proxy listening on %s", s5cfg.Listen)
	return nil
}

func (c *Client) startForward(fwdCfg config.ForwardConfig) error {
	fwd, err := proxy.NewForwarder(fwdCfg.Listen, fwdCfg.Destination, fwdCfg.Protocol)
	if err != nil {
		return err
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		fwd.Serve(func(destination string) (chan<- []byte, <-chan []byte, error) {
			return c.openStream(fwdCfg.Protocol, destination)
		})
	}()

	c.log.Info("Forward %s -> %s (%s) listening", fwdCfg.Listen, fwdCfg.Destination, fwdCfg.Protocol)
	return nil
}

// openStream creates a new data stream through the tunnel.
func (c *Client) openStream(protocol, destination string) (chan<- []byte, <-chan []byte, error) {
	if c.session == nil || !c.session.Authenticated {
		return nil, nil, fmt.Errorf("not connected")
	}

	streamID := icmp.GenerateStreamID()
	stream := c.session.AddStreamWithID(streamID, protocol, destination)

	// Send connect request
	req := &icmp.ConnectRequest{
		StreamID:    streamID,
		Protocol:    protocol,
		Destination: destination,
	}
	reqData := icmp.EncodeConnectRequest(req)

	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: c.session.ID,
		Data:      reqData,
		Priority:  2,
	}
	c.sendQueue <- pkt

	// Wait for connect ACK with timeout
	timeout := time.After(10 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-timeout:
			c.session.RemoveStream(streamID)
			return nil, nil, fmt.Errorf("connect timeout for stream %d", streamID)
		case <-tick.C:
			c.session.Mu.RLock()
			s, ok := c.session.Streams[streamID]
			c.session.Mu.RUnlock()
			if ok && s.State == icmp.StreamStateOpen {
				goto connected
			}
		case <-c.ctx.Done():
			return nil, nil, fmt.Errorf("client stopping")
		}
	}

connected:
	// Start uplink goroutine (reads from sendCh, sends over tunnel)
	sendCh := make(chan []byte, 8192)

	c.wg.Add(1)
	go c.recoverableRun(fmt.Sprintf("uplink-%d", streamID), func() {
		c.uplinkWorker(streamID, sendCh, stream)
	})

	return sendCh, stream.DataChan, nil
}

// uplinkWorker reads from the send channel and sends data through the tunnel.
func (c *Client) uplinkWorker(streamID uint16, sendCh <-chan []byte, stream *icmp.Stream) {
	defer c.session.RemoveStream(streamID)

	for {
		select {
		case data, ok := <-sendCh:
			if !ok {
				// Channel closed — send close notification
				c.sendControl(icmp.ControlClose, uint32(streamID))
				return
			}

			payload := icmp.EncodeStreamData(streamID, data)
			pkt := &icmp.TunnelPacket{
				Type:      icmp.TypeData,
				SessionID: c.session.ID,
				Data:      payload,
				StreamIDs: []uint16{streamID},
			}

			select {
			case c.sendQueue <- pkt:
				atomic.AddUint64(&stream.TxBytes, uint64(len(data)))
			case <-c.ctx.Done():
				return
			}

		case <-stream.Done:
			return

		case <-c.ctx.Done():
			return
		}
	}
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
