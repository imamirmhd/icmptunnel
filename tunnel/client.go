// Package tunnel implements the core client and server tunnel logic.
package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/user/icmptunnel/auth"
	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/crypto"
	"github.com/user/icmptunnel/evasion"
	"github.com/user/icmptunnel/icmp"
	"github.com/user/icmptunnel/logger"
	"github.com/user/icmptunnel/proxy"
)

// Client manages the client side of the ICMP tunnel.
type Client struct {
	cfg        *config.ClientConfig
	socket     *icmp.Socket
	encryptor  crypto.Encryptor
	evasion    *evasion.Manager
	sessionMgr *icmp.SessionManager
	session    *icmp.Session
	serverAddr net.IP
	localAddr  net.IP
	streams    map[uint16]chan []byte
	streamsMu  sync.RWMutex
	pendingStreams map[uint16]chan error
	pendingAcks    map[uint32]chan error
	pendingMu      sync.Mutex
	socks5     []*proxy.Socks5Server
	forwarders []*proxy.Forwarder
	lastServerActivity time.Time
	log                *logger.Logger
	done               chan struct{}
	wg                 sync.WaitGroup
	authCh             chan error
	started            bool
	mu                 sync.Mutex
	reconnecting       bool
	reconMu            sync.Mutex

	// Aggregation & Pacing
	aggMu      sync.Mutex
	aggData    []byte
	aggStreams map[uint16]bool
	aggTimer   *time.Timer
	maxAgg     int
	pollTicks  int
	sessionMu  sync.RWMutex

	// Worker Pool & Sender
	jobQueue   chan *packetJob
	sendQueue  chan *sendJob
	ctrlQueue  chan *sendJob
}

// NewClient creates a new tunnel client.
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("client")

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

	serverAddr := net.ParseIP(cfg.ServerAddr)
	if serverAddr == nil && !cfg.Spoof.Enabled {
		sock.Close()
		return nil, fmt.Errorf("invalid server address: %s", cfg.ServerAddr)
	}

	ev := evasion.NewManager(cfg.Evasion)

	return &Client{
		cfg:        cfg,
		socket:     sock,
		encryptor:  enc,
		evasion:    ev,
		sessionMgr: icmp.NewSessionManagerWithParams(5*time.Minute, cfg.Transport.WindowSize/2, cfg.Transport.WindowSize),
		serverAddr: serverAddr,
		streams:        make(map[uint16]chan []byte),
		pendingStreams: make(map[uint16]chan error),
		pendingAcks:    make(map[uint32]chan error),
		aggData:        nil,
		aggStreams:     make(map[uint16]bool),
		log:            log,
		done:           make(chan struct{}),
		authCh:         make(chan error, 1),
		maxAgg:         cfg.ICMP.MaxPacketSize - 64, // Leave some room
		jobQueue:       make(chan *packetJob, 16384),
		sendQueue:      make(chan *sendJob, 16384),
		ctrlQueue:      make(chan *sendJob, 1024),
	}, nil
}

// Start runs the tunnel client.
func (c *Client) Start() error {
	c.log.Info("Starting ICMP tunnel client")

	// Get local address
	// Bind socket to configured address (or 0.0.0.0 if empty)
	bindAddr := c.cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
		c.localAddr = net.IPv4zero // Let kernel choose source IP
	} else {
		c.localAddr = net.ParseIP(bindAddr)
		if c.localAddr == nil {
			return fmt.Errorf("invalid bind address: %s", bindAddr)
		}
	}

	if err := c.socket.Bind(bindAddr); err != nil {
		return fmt.Errorf("binding socket: %w", err)
	}
	
	c.log.Info("Local address: %s (or kernel selected)", bindAddr)
	c.log.Info("Server address: %s", c.serverAddr)
	c.log.Info("Fragmentation enabled: %v", c.cfg.Evasion.Fragmentation.Enabled)

	// Start loops before authentication!
	// authenticate() depends on sendQueue being processed.
	c.mu.Lock()
	c.started = true
	c.mu.Unlock()

	c.wg.Add(3 + 16 + 1) // Heartbeat + Retransmit + Stats + Sender + Workers
	go c.heartbeatLoop()
	go c.retransmitLoop() 
	go c.statsLoop()
	go c.senderLoop() // Processes sendQueue
	for i := 0; i < 16; i++ {
		go c.workerLoop(i)
	}

	// Authenticate
	if err := c.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	c.log.Info("Authentication successful")

	// Start SOCKS5 proxies
	maxData := c.calculateMaxStreamData()
	for _, scfg := range c.cfg.Socks5 {
		s := proxy.NewSocks5Server(scfg.Listen, scfg.Username, scfg.Password, maxData,
			c.handleConnect, c.handleData, c.handleClose)
		if err := s.Start(); err != nil {
			return fmt.Errorf("starting SOCKS5 proxy on %s: %w", scfg.Listen, err)
		}
		c.socks5 = append(c.socks5, s)
		c.log.Info("SOCKS5 proxy started on %s", scfg.Listen)
	}

	// Start forwarders
	for _, fcfg := range c.cfg.Forwards {
		f := proxy.NewForwarder(fcfg.Listen, fcfg.Destination, fcfg.Protocol, maxData,
			c.handleConnect, c.handleData, c.handleClose)
		if err := f.Start(); err != nil {
			return fmt.Errorf("starting forwarder %s->%s: %w", fcfg.Listen, fcfg.Destination, err)
		}
		c.forwarders = append(c.forwarders, f)
		c.log.Info("Forwarder started: %s -> %s (%s)", fcfg.Listen, fcfg.Destination, fcfg.Protocol)
	}

	return nil
}

// Stop shuts down the tunnel client.
func (c *Client) Stop() {
	c.log.Info("Stopping tunnel client")
	close(c.done)

	for _, s := range c.socks5 {
		s.Stop()
	}
	for _, f := range c.forwarders {
		f.Stop()
	}

	c.socket.Close()
	c.wg.Wait()
}

// Wait blocks until the client is stopped.
func (c *Client) Wait() {
	c.wg.Wait()
}

func (c *Client) authenticate() error {
	session := c.getSession()
	if session == nil {
		c.log.Info("Creating initial session...")
		session = c.sessionMgr.CreateSession(c.serverAddr)
		c.sessionMu.Lock()
		c.session = session
		c.sessionMu.Unlock()
	}

	// Build auth packet with token
	authData := []byte(c.cfg.AuthToken)

	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeAuth,
		Flags:     icmp.FlagAuth,
		SessionID: session.ID,
		SeqNum:    session.GetNextSeq(),
		Data:      authData,
	}

	if err := c.sendTunnelPacket(pkt); err != nil {
		return fmt.Errorf("sending auth: %w", err)
	}

	// If main loop is running, wait on channel
	c.mu.Lock()
	running := c.started
	c.mu.Unlock()

	if running {
		c.log.Info("Waiting for auth via main loop...")
		select {
		case err := <-c.authCh:
			return err
		case <-time.After(auth.AuthTimeout):
			return fmt.Errorf("authentication timed out")
		}
	}

	// Otherwise use local loop (initial start)
	deadline := time.Now().Add(auth.AuthTimeout)
	fragBuf := evasion.NewFragmentBuffer()

	for time.Now().Before(deadline) {
		select {
		case <-c.done:
			return fmt.Errorf("client stopping")
		default:
		}

		srcIP, icmpType, icmpID, icmpSeq, rawPayload, origBuf, err := c.socket.Receive()
		if err != nil {
			if origBuf != nil {
				icmp.ReleaseBuffer(origBuf)
			}
			continue
		}

		if icmpType != 0 && icmpType != 8 {
			continue
		}
		session = c.getSession()
		if icmpType == 8 && session != nil && icmpID == session.OutboundICMPID && srcIP.Equal(c.localAddr) {
			icmp.ReleaseBuffer(origBuf)
			continue
		}

		c.log.Debug("Auth loop received ICMP type %d from %s", icmpType, srcIP)

		// Handle fragmentation and evasion
		var reassembledData []byte
		if c.cfg.Evasion.Fragmentation.Enabled {
			data, complete, err := fragBuf.Add(rawPayload)
			if err == nil {
				if !complete {
					continue
				}
				reassembledData = data
			} else {
				// Not a fragment, use direct
				reassembledData = rawPayload
			}
		} else {
			reassembledData = rawPayload
		}

		// Apply other evasion reversal
		processed, err := c.evasion.Unapply([][]byte{reassembledData})
		if err != nil {
			continue
		}
		reassembledData = processed

		decrypted, err := c.encryptor.Decrypt(reassembledData)
		if err != nil {
			continue
		}

		tunnelPkt, err := icmp.DecodeTunnelPacket(decrypted)
		if err != nil {
			continue
		}

		tunnelPkt.ICMPID = icmpID
		tunnelPkt.ICMPSeq = icmpSeq

		c.log.Debug("Auth loop decoded pkt: Type=%d, SessionID=%08x, Seq=%d", tunnelPkt.Type, tunnelPkt.SessionID, tunnelPkt.SeqNum)
		if tunnelPkt.Type == icmp.TypeControl && len(tunnelPkt.Data) > 0 {
			c.log.Debug("Auth loop control subtype: %d", tunnelPkt.Data[0])
		}

		session = c.getSession()
		if session != nil && tunnelPkt.SessionID == session.ID {
			if tunnelPkt.Type == icmp.TypeControl {
				if len(tunnelPkt.Data) > 0 && tunnelPkt.Data[0] == icmp.ControlAuthOK {
					session.Authenticated = true
					session.MarkReceived(tunnelPkt.SeqNum) // Advance sequence
					session.ProcessIncoming(tunnelPkt)   // Captures NAT info
					
					// Send ACK for AuthOK so server stops retransmitting
					ackPkt := &icmp.TunnelPacket{
						Type:      icmp.TypeControl,
						SessionID: session.ID,
						SeqNum:    0, // ACKs don't need to be sequenced
						Data:      icmp.EncodeControlMessage(icmp.ControlACK, tunnelPkt.SeqNum),
					}
					c.sendTunnelPacket(ackPkt)
					
					return nil
				}
				if len(tunnelPkt.Data) > 0 && tunnelPkt.Data[0] == icmp.ControlAuthFail {
					icmp.ReleaseBuffer(origBuf)
					return fmt.Errorf("server rejected authentication")
				}
			}
		}
		icmp.ReleaseBuffer(origBuf)
	}

	return fmt.Errorf("authentication timed out")
}

func (c *Client) handleConnect(protocol, destination string) (uint16, chan []byte, error) {
	var streamID uint16
	for i := 0; i < 10; i++ {
		streamID = icmp.GenerateStreamID()
		c.streamsMu.RLock()
		_, exists := c.streams[streamID]
		c.streamsMu.RUnlock()
		if !exists {
			break
		}
		if i == 9 {
			return 0, nil, fmt.Errorf("failed to generate unique stream ID after 10 attempts")
		}
	}

	c.log.Debug("Generated streamID %d for connection to %s", streamID, destination)
	responseChan := make(chan []byte, 8192)
	statusChan := make(chan error, 1)

	c.streamsMu.Lock()
	c.streams[streamID] = responseChan
	c.streamsMu.Unlock()

	c.pendingMu.Lock()
	c.pendingStreams[streamID] = statusChan
	c.pendingMu.Unlock()

	// Send connect request to server
	req := &icmp.ConnectRequest{
		StreamID:    streamID,
		Protocol:    protocol,
		Destination: destination,
	}

	controlData := icmp.EncodeConnectRequest(req)
	session := c.getSession()
	if session == nil {
		return 0, nil, fmt.Errorf("no active session")
	}

	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: session.ID,
		SeqNum:    session.GetNextSeq(),
		Data:      controlData,
	}
	// Send connect request to server reliably
	if err := c.sendPacketReliable(pkt, 5*time.Second, 15); err != nil {
		c.handleClose(streamID)
		return 0, nil, err
	}

	// Wait for ConnectACK (which carries status)
	select {
	case err := <-statusChan:
		if err != nil {
			c.handleClose(streamID)
			return 0, nil, err
		}
		c.log.Info("Stream %d established to %s", streamID, destination)
		return streamID, responseChan, nil
	case <-time.After(120 * time.Second):
		c.handleClose(streamID)
		return 0, nil, fmt.Errorf("connect timeout waiting for status")
	}
}

func (c *Client) handleData(streamID uint16, data []byte) error {
	session := c.getSession()
	if session == nil {
		return fmt.Errorf("no active session")
	}

	// Flow Control: Block if congestion window is full
	// Use a context with timeout to avoid blocking forever
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := session.WaitSendCapacity(ctx); err != nil {
		// If timeout, we drop the packet (or could buffer it, but dropping is better for real-time)
		c.log.Warn("Congestion window full, dropping packet for stream %d", streamID)
		return nil // Return nil so caller doesn't close stream immediately, just partial drop
	}

	c.aggMu.Lock()
	defer c.aggMu.Unlock()

	// Check if stream is still valid/open
	c.streamsMu.RLock()
	_, ok := c.streams[streamID]
	c.streamsMu.RUnlock()
	if !ok {
		return fmt.Errorf("stream %d closed", streamID)
	}

	c.log.Debug("Aggregating %d bytes for stream %d (current agg: %d)", len(data), streamID, len(c.aggData))
	c.aggData = append(c.aggData, icmp.EncodeStreamData(streamID, data)...)
	c.aggStreams[streamID] = true

	if len(c.aggData) >= c.maxAgg {
		c.flushAggBuffer()
	} else if c.aggTimer == nil {
		c.aggTimer = time.AfterFunc(2*time.Millisecond, func() {
			c.aggMu.Lock()
			c.flushAggBuffer()
			c.aggMu.Unlock()
		})
	}

	return nil
}

func (c *Client) flushAggBuffer() {
	if len(c.aggData) == 0 {
		return
	}

	if c.aggTimer != nil {
		c.aggTimer.Stop()
		c.aggTimer = nil
	}

	data := c.aggData
	c.aggData = nil
	streamIDs := make([]uint16, 0, len(c.aggStreams))
	for id := range c.aggStreams {
		streamIDs = append(streamIDs, id)
	}
	c.aggStreams = make(map[uint16]bool)

	session := c.getSession()
	if session == nil {
		return
	}

	// Compression
	compressed := data
	pktFlags := uint8(0)
	if len(data) > 128 {
		comp := session.Compress(data)
		if len(comp) < len(data) {
			compressed = comp
			pktFlags |= icmp.FlagCompressed
		}
	}
	
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeData,
		Flags:     pktFlags,
		SessionID: session.ID,
		SeqNum:    session.GetNextSeq(),
		Data:      compressed,
		StreamIDs: streamIDs,
	}

	session.RecordSent(pkt)
	c.log.Debug("Sending data packet: seq=%d, size=%d, flags=%x", pkt.SeqNum, len(pkt.Data), pkt.Flags)
	go c.sendTunnelPacket(pkt)
}

func (c *Client) retransmitLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			session := c.getSession()
			if session == nil {
				continue
			}
			retrans := session.GetRetransmissions()
			for _, p := range retrans {
				c.log.Debug("Retransmitting packet %d", p.SeqNum)
				go c.sendTunnelPacket(p)
			}
		}
	}
}

func (c *Client) statsLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			// Log performance metrics
		}
	}
}

func (c *Client) handleControl(subtype uint8, value uint32, rawPayload []byte) {
	streamID := uint16(value)
	switch subtype {
	case icmp.ControlConnectACK:
		c.pendingMu.Lock()
		if ch, ok := c.pendingStreams[streamID]; ok {
			ch <- nil
			delete(c.pendingStreams, streamID)
		}
		c.pendingMu.Unlock()

	case icmp.ControlConnectFail:
		c.pendingMu.Lock()
		if ch, ok := c.pendingStreams[streamID]; ok {
			ch <- fmt.Errorf("server failed to connect to destination")
			delete(c.pendingStreams, streamID)
		}
		c.pendingMu.Unlock()

	case icmp.ControlClose:
		c.handleClose(streamID)

	case icmp.ControlACK:
		// Server acked our data/control packet
		session := c.getSession()
		if session != nil {
			session.ProcessACK(value, nil)
		}
		// Sync handling: notify any synchronous waiters
		c.pendingMu.Lock()
		if ch, ok := c.pendingAcks[value]; ok {
			ch <- nil
			delete(c.pendingAcks, value)
		}
		c.pendingMu.Unlock()

	case icmp.ControlSACK:
		sack, err := icmp.DecodeSACK(rawPayload)
		session := c.getSession()
		if err == nil && session != nil {
			session.ProcessACK(sack.AckedSeq, sack.Blocks)
		}

	case icmp.ControlAuthOK:
		session := c.getSession()
		if session != nil {
			session.Authenticated = true
		}
		select {
		case c.authCh <- nil:
		default:
		}

	case icmp.ControlAuthFail:
		c.log.Warn("Received AuthFail from server, triggering reconnect")
		select {
		case c.authCh <- fmt.Errorf("server rejected authentication"):
		default:
		}
		c.abortPending(fmt.Errorf("server rejected authentication"))
		// If we are running, trigger reconnect
		c.triggerReconnect()
	}
}

func (c *Client) handleClose(streamID uint16) {
	c.streamsMu.Lock()
	if ch, ok := c.streams[streamID]; ok {
		close(ch)
		delete(c.streams, streamID)
	}
	c.streamsMu.Unlock()

	c.pendingMu.Lock()
	delete(c.pendingStreams, streamID)
	c.pendingMu.Unlock()

	session := c.getSession()
	if session != nil {
		// Send close reliably.
		// Construct the packet.
		closePkt := &icmp.TunnelPacket{
			Type:      icmp.TypeControl,
			SessionID: session.ID,
			SeqNum:    session.GetNextSeq(),
			Data:      icmp.EncodeControlMessage(icmp.ControlClose, uint32(streamID)),
		}

		// Use a separate goroutine to retry the close message
		go func() {
			// Try hard to send the close message
			backoff := 100 * time.Millisecond
			for i := 0; i < 5; i++ {
				select {
				case <-c.done:
					return
				default:
				}

				if err := c.sendTunnelPacket(closePkt); err == nil {
					return // Success
				}
				
				// If queue full, wait a bit and retry
				time.Sleep(backoff)
				backoff *= 2
			}
			c.log.Warn("Failed to send ControlClose for stream %d after retries", streamID)
		}()
	}
}

func (c *Client) sendPacketReliable(pkt *icmp.TunnelPacket, timeout time.Duration, maxRetries int) error {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if maxRetries <= 0 {
		maxRetries = 10
	}
	
	ackChan := make(chan error, 1)
	c.pendingMu.Lock()
	c.pendingAcks[pkt.SeqNum] = ackChan
	c.pendingMu.Unlock()
	
	defer func() {
		c.pendingMu.Lock()
		delete(c.pendingAcks, pkt.SeqNum)
		c.pendingMu.Unlock()
	}()

	for i := 0; i <= maxRetries; i++ {
		if err := c.sendTunnelPacket(pkt); err != nil {
			return err
		}

		select {
		case err := <-ackChan:
			return err
		case <-c.done:
			return fmt.Errorf("client stopping")
		case <-time.After(timeout):
			// retry
			c.log.Debug("Packet %d timeout, retry %d", pkt.SeqNum, i+1)
		}
	}

	return fmt.Errorf("packet %d failed after %d retries", pkt.SeqNum, maxRetries)
}

func (c *Client) getSession() *icmp.Session {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.session
}

func (c *Client) sendToStream(streamID uint16, data []byte) {
	c.streamsMu.RLock()
	ch, ok := c.streams[streamID]
	c.streamsMu.RUnlock()
	if !ok {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			c.log.Debug("Recovered from panic sending to stream %d (likely closed)", streamID)
		}
	}()

	// Use a shorter timeout to prevent blocking the receive loop
	select {
	case ch <- data:
	case <-time.After(50 * time.Millisecond):
		c.log.Warn("Stream %d buffer full, dropping packet", streamID)
	case <-c.done:
		return
	}
}

func (c *Client) sendTunnelPacket(pkt *icmp.TunnelPacket) error {
	priority := pkt.Type == icmp.TypeAuth || pkt.Type == icmp.TypeControl
	if c.cfg.Encryption.Enabled {
		pkt.Flags |= icmp.FlagEncrypted
	}

	payload := pkt.Encode()
	encrypted, err := c.encryptor.Encrypt(payload)
	if err != nil {
		return err
	}

	// Apply evasion techniques
	packets, err := c.evasion.Apply(encrypted)
	if err != nil {
		return err
	}

	for _, p := range packets {
		delay := c.evasion.PreSendDelay()
		if delay > 0 {
			time.Sleep(delay)
		}

		session := c.getSession()
		if session == nil {
			return fmt.Errorf("no active session")
		}

		// Use stable outbound ICMP flow
		icmpID := session.OutboundICMPID
		icmpSeq := session.GetNextICMPSeq()
		if err := c.sendICMP(p, icmpID, icmpSeq, priority); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) sendICMP(payload []byte, icmpID, icmpSeq uint16, priority bool) error {
	if c.cfg.Spoof.Enabled {
		spoofHdr := &icmp.SpoofHeader{
			RealClientIP: c.localAddr,
			RouteFlag:    icmp.RouteDirect,
			RelayIP:      net.ParseIP(c.cfg.Spoof.RelayAddr),
		}
		if c.cfg.Spoof.RouteViaRelay {
			spoofHdr.RouteFlag = icmp.RouteViaRelay
		}
		spoofedPayload, err := icmp.BuildSpoofedPayload(spoofHdr, payload)
		if err != nil {
			return err
		}
		relayIP := net.ParseIP(c.cfg.Spoof.RelayAddr)
		c.log.Debug("Sending ICMP Echo Request to server %s via relay %s, ID=%d, Seq=%d", c.serverAddr, relayIP, icmpID, icmpSeq)
		return c.socket.SendEcho(c.serverAddr, relayIP, icmpID, icmpSeq, spoofedPayload)
	}

	c.log.Debug("Sending ICMP Echo Request to server %s, ID=%d, Seq=%d", c.serverAddr, icmpID, icmpSeq)
	
	// Queue send
	c.queueSend(c.localAddr, c.serverAddr, icmpID, icmpSeq, payload, false, priority)
	return nil
}

func (c *Client) queueSend(srcIP, destIP net.IP, icmpID, icmpSeq uint16, payload []byte, isReply bool, priority bool) {
	job := &sendJob{
		srcIP:   srcIP,
		destIP:  destIP,
		icmpID:  icmpID,
		icmpSeq: icmpSeq,
		payload: payload,
		reply:   isReply,
	}

	queue := c.sendQueue
	if priority {
		queue = c.ctrlQueue
	}

	select {
	case queue <- job:
	default:
		if priority {
			c.log.Warn("Priority queue full, dropping packet to %s", destIP)
		} else {
			c.log.Warn("Send queue full, dropping packet to %s", destIP)
		}
	}
}

func (c *Client) senderLoop() {
	defer c.wg.Done()
	for {
		var job *sendJob
		select {
		case <-c.done:
			return
		case job = <-c.ctrlQueue:
			// Priority job
		default:
			// No priority job, check data queue
			select {
			case <-c.done:
				return
			case job = <-c.ctrlQueue:
				// Priority job arrived
			case job = <-c.sendQueue:
				// Data job
			}
		}

		var err error
		if job.reply {
			err = c.socket.SendReply(job.srcIP, job.destIP, job.icmpID, job.icmpSeq, job.payload)
		} else {
			err = c.socket.SendEcho(job.srcIP, job.destIP, job.icmpID, job.icmpSeq, job.payload)
		}

		if err != nil {
			c.log.Error("Send error: %v", err)
		}
	}
}

func (c *Client) workerLoop(id int) {
	defer c.wg.Done()
	// fragBuf defined locally per worker is wrong if we want sequential frag reassembly
	// Just like server, we will handle frags in receiveLoop if needed.
	
	for job := range c.jobQueue {
		c.processPacketJob(job)
	}
}

func (c *Client) processPacketJob(job *packetJob) {
	defer icmp.ReleaseBuffer(job.origBuf)

	icmpID := job.icmpID
	icmpSeq := job.icmpSeq
	rawPayload := job.payload
	
	var reassembledData []byte = rawPayload
	
	// Apply other evasion reversal (Padding, Resizing)
	processedData, err := c.evasion.Unapply([][]byte{reassembledData})
	if err == nil {
		reassembledData = processedData
	} else {
		c.log.Debug("Evasion Unapply failed: %v", err)
	}

	decrypted, err := c.encryptor.Decrypt(reassembledData)
	if err != nil {
		c.log.Debug("Decryption failed: %v", err)
		return
	}

	tunnelPkt, err := icmp.DecodeTunnelPacket(decrypted)
	if err != nil {
		c.log.Debug("Decoded tunnel packet failed: %v", err)
		return
	}

	tunnelPkt.ICMPID = icmpID
	tunnelPkt.ICMPSeq = icmpSeq

	session := c.getSession()
	if session != nil && tunnelPkt.SessionID == session.ID {
		// Decompression
		if (tunnelPkt.Flags & icmp.FlagCompressed) != 0 {
			decomp, err := session.Decompress(tunnelPkt.Data)
			if err == nil {
				tunnelPkt.Data = decomp
				tunnelPkt.Flags &= ^icmp.FlagCompressed
			} else {
				c.log.Error("Decompress failed: %v", err)
				return
			}
		}

		c.log.Debug("Received tunnel pkt: Type=%d, Seq=%d", tunnelPkt.Type, tunnelPkt.SeqNum)

		// Reliability
		// Need to ensure sequential processing for session state updates?
		// session.ProcessIncoming handles locking internally.
		// BUT if we process Control messages out of order (e.g. AuthOK), it might matter?
		// Worker pool processes in parallel.
		// Session state (lock) protects internals.
		// Logic should be fine.

		pkts := session.ProcessIncoming(tunnelPkt)
		if pkts == nil && session.IsDuplicate(tunnelPkt.SeqNum) {
			// Duplicate handling
			if tunnelPkt.Type == icmp.TypeControl {
				// Re-ack control messages (like Connect/Close)
				subtype, value, _ := icmp.DecodeControlMessage(tunnelPkt.Data)
				c.handleControl(subtype, value, tunnelPkt.Data)
			}
			return
		}

		for _, p := range pkts {
			switch p.Type {
			case icmp.TypeData:
				// data packet
				// Expand stream data
				entries, err := icmp.DecodeAllStreamData(p.Data)
				if err == nil {
					for _, entry := range entries {
						c.sendToStream(entry.StreamID, entry.Data)
					}
				}
				
				// ACK data
				ackPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					SeqNum:    0,
					Data:      icmp.EncodeControlMessage(icmp.ControlACK, p.SeqNum),
				}
				go c.sendTunnelPacket(ackPkt)

			case icmp.TypeControl:
				subtype, value, _ := icmp.DecodeControlMessage(p.Data)
				c.handleControl(subtype, value, p.Data)
				
				// Generic ACK for control types
				shouldGenericAck := false
				switch subtype {
				case icmp.ControlACK, icmp.ControlSACK, icmp.ControlHeartbeat, icmp.ControlAuthOK, icmp.ControlAuthFail:
					// No ack needed
				default:
					shouldGenericAck = true
				}
				if shouldGenericAck {
					ackPkt := &icmp.TunnelPacket{
						Type:      icmp.TypeControl,
						SessionID: session.ID,
						SeqNum:    0,
						Data:      icmp.EncodeControlMessage(icmp.ControlACK, p.SeqNum),
					}
					go c.sendTunnelPacket(ackPkt)
				}
			}
		}
		
		c.sessionMgr.TouchSession(tunnelPkt.SessionID)
	}
}

func (c *Client) receiveLoop() {
	defer c.wg.Done()

	fragBuf := evasion.NewFragmentBuffer()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		srcIP, icmpType, icmpID, icmpSeq, rawPayload, origBuf, err := c.socket.Receive()
		if err != nil {
			if origBuf != nil {
				icmp.ReleaseBuffer(origBuf)
			}
			// ... (existing error handling)
			continue
		}

		// Client accepts Echo Reply (0) and Echo Request (8).
		// Echo Requests from the server are "push" packets for high-throughput downlink.
		// Only filter out our own outbound Echo Requests (reflected back by the socket).
		if icmpType != 0 && icmpType != 8 {
			icmp.ReleaseBuffer(origBuf)
			continue
		}

		session := c.getSession()
		if session == nil {
			icmp.ReleaseBuffer(origBuf)
			continue
		}

		// Ignore reflected packets we sent ourselves (same outbound ICMP ID from local IP)
		if icmpType == 8 && icmpID == session.OutboundICMPID && srcIP.Equal(c.localAddr) {
			icmp.ReleaseBuffer(origBuf)
			continue
		}

		c.log.Debug("Received ICMP type %d from %s, len %d", icmpType, srcIP, len(rawPayload))

		// Handle fragmentation if enabled
		var packetData []byte = rawPayload
		if c.cfg.Evasion.Fragmentation.Enabled {
			// Keeping single-threaded frag handling for now
			data, complete, err := fragBuf.Add(rawPayload)
			if err == nil {
				if !complete {
					// We must hold onto origBuf or copy data?
					// FragmentBuffer copies data internally usually.
					// So we can release origBuf.
					icmp.ReleaseBuffer(origBuf)
					continue // Waiting for more fragments
				}
				packetData = data
				// If completed, we have a clear packet.
				// However, if FragmentBuffer returned a slice to internal buffer, we proceed.
				// We release origBuf now because fragBuf has the data.
				icmp.ReleaseBuffer(origBuf)
				// Wait, if packetData is used later in worker, we must ensure it lives.
				// If fragBuf is reused, we might have issue.
				// Assume fragBuf returns fresh slice or copy. 
				// BUT if we pass packetData to worker, and worker is slow, and fragBuf reuses...
				// For safety, let's copy if coming from fragBuf.
				packetData = append([]byte(nil), data...)
				
				// Dispatch without origBuf because we already released/copied
				job := &packetJob{
					srcIP:    srcIP,
					icmpType: icmpType,
					icmpID:   icmpID,
					icmpSeq:  icmpSeq,
					payload:  packetData,
					origBuf:  nil, // Already handled/copied
				}
				select {
				case c.jobQueue <- job:
				default:
					c.log.Warn("Job queue full")
				}
				continue
			} else {
				// Not a fragment, use direct payload
				packetData = rawPayload
			}
		} else {
			packetData = rawPayload
		}

		// Dispatch
		// If frag was disabled or failed, packetData == rawPayload == part of origBuf.
		// So we pass origBuf to worker.
		job := &packetJob{
			srcIP:    srcIP,
			icmpType: icmpType,
			icmpID:   icmpID,
			icmpSeq:  icmpSeq,
			payload:  packetData,
			origBuf:  origBuf,
		}

		select {
		case c.jobQueue <- job:
		default:
			c.log.Warn("Job queue full")
			icmp.ReleaseBuffer(origBuf)
		}
	}
}


func (c *Client) heartbeatLoop() {
	defer c.wg.Done()
	heartbeatTicker := time.NewTicker(10 * time.Second)
	pollTicker := time.NewTicker(2 * time.Millisecond)
	defer heartbeatTicker.Stop()
	defer pollTicker.Stop()

	// Start receiveLoop once
	c.wg.Add(1)
	go c.receiveLoop()

	// Initial activity
	c.lastServerActivity = time.Now()

	for {
		select {
		case <-c.done:
			return
		case <-heartbeatTicker.C:
			session := c.getSession()
			if session == nil {
				continue
			}

			// Send heartbeat with timestamp
			now := time.Now().UnixNano()
			ts := make([]byte, 8)
			binary.BigEndian.PutUint64(ts, uint64(now))
			
			pkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: session.ID,
				SeqNum:    0, // Heartbeats don't need to be in the reliable sequence
				Data:      append([]byte{icmp.ControlHeartbeat}, ts...),
			}
			go c.sendTunnelPacket(pkt)

			// Check for timeout
			if time.Since(c.lastServerActivity) > 60*time.Second {
				c.log.Warn("Tunnel timeout, attempting to reconnect...")
				c.triggerReconnect()
			}
		case <-pollTicker.C:
			session := c.getSession()
			if session == nil || !session.Authenticated {
				continue
			}

			c.streamsMu.RLock()
			activeStreams := len(c.streams)
			c.streamsMu.RUnlock()

			// Baseline polling every 200ms when idle
			// Since pollTicker is 2ms, 200ms is 100 ticks.
			c.pollTicks++
			if activeStreams == 0 && c.pollTicks < 100 {
				continue
			}
			c.pollTicks = 0

			// Scale burst size proportionally with active streams.
			// Each active stream needs ~1 slot per read cycle to keep data flowing.
			// 2ms * 500 ticks/sec * burst = slots/sec available for downlink.
			// For 50 streams: burst ~50 → 25000 slots/sec → ~34 MB/s max
			burstSize := 5
			if activeStreams == 0 {
				burstSize = 1
			} else if activeStreams >= 40 {
				burstSize = activeStreams + 20
			} else if activeStreams >= 20 {
				burstSize = activeStreams + 10
			} else if activeStreams >= 5 {
				burstSize = activeStreams + 5
			} else {
				burstSize = 10
			}

			for i := 0; i < burstSize; i++ {
				sack := session.GenerateSACK()
				sackPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: session.ID,
					SeqNum:    0, // SACK polls don't need to be reliable/sequenced
					Data:      icmp.EncodeSACK(sack),
				}
				go c.sendTunnelPacket(sackPkt)
			}
		}
	}
}

func (c *Client) triggerReconnect() {
	c.reconMu.Lock()
	if c.reconnecting {
		c.reconMu.Unlock()
		return
	}
	c.reconnecting = true
	c.reconMu.Unlock()
	go c.reconnect()
}

func (c *Client) reconnect() {
	defer func() {
		c.reconMu.Lock()
		c.reconnecting = false
		c.reconMu.Unlock()
	}()

	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.log.Info("Reconnecting... (backoff %v)", backoff)
		
		// Reuse existing session manager to avoid leaking cleanup loops
		newSession := c.sessionMgr.CreateSession(c.serverAddr)
		newSession.AuthToken = c.cfg.AuthToken
		
		c.sessionMu.Lock()
		c.session = newSession
		c.sessionMu.Unlock()

		if err := c.authenticate(); err == nil {
			c.log.Info("Reconnected successfully")
			c.lastServerActivity = time.Now()
			return
		}

		select {
		case <-c.done:
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) abortPending(err error) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	for seq, ch := range c.pendingAcks {
		select {
		case ch <- err:
		default:
		}
		delete(c.pendingAcks, seq)
	}

	for id, ch := range c.pendingStreams {
		select {
		case ch <- err:
		default:
		}
		delete(c.pendingStreams, id)
	}
}

func getOutboundIP(target net.IP) net.IP {
	// If target is unspecified (e.g. listener), default to internet
	if target == nil || target.IsUnspecified() {
		target = net.ParseIP("8.8.8.8")
	}
	
	conn, err := net.Dial("udp", fmt.Sprintf("%s:80", target))
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func (c *Client) calculateMaxStreamData() int {
	// Socket.Send check: 20 (IP) + 8 (ICMP) + len(payload) > s.maxPacketSize + 20
	// To treat maxPacketSize as MTU, we need 20 + 8 + len(payload) <= s.maxPacketSize
	// len(payload) <= s.maxPacketSize - 28
	room := c.cfg.ICMP.MaxPacketSize - 28

	// Subtract Evasion overhead
	room -= c.evasion.Overhead()

	// Subtract Encryption overhead
	room -= c.encryptor.Overhead()

	// Subtract Tunnel header (11) and Stream Data header (4)
	room -= icmp.TunnelHeaderSize
	room -= icmp.StreamDataHeaderSize

	if room < 64 {
		room = 64 // Minimum safety
	}
	c.log.Debug("Calculated max stream data size: %d", room)
	return room
}
