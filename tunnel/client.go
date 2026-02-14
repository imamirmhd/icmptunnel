// Package tunnel implements the core client and server tunnel logic.
package tunnel

import (
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
	pendingAcks    map[uint16]chan error
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
	aggMu     sync.Mutex
	aggData   []byte
	aggTimer  *time.Timer
	maxAgg    int
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
		sessionMgr: icmp.NewSessionManager(5 * time.Minute),
		serverAddr: serverAddr,
		streams:        make(map[uint16]chan []byte),
		pendingStreams: make(map[uint16]chan error),
		pendingAcks:    make(map[uint16]chan error),
		log:            log,
		done:       make(chan struct{}),
		authCh:     make(chan error, 1),
		maxAgg:     cfg.ICMP.MaxPacketSize - 64, // Leave some room
	}, nil
}

// Start runs the tunnel client.
func (c *Client) Start() error {
	c.log.Info("Starting ICMP tunnel client")

	// Get local address
	c.localAddr = getOutboundIP(c.serverAddr)
	c.log.Info("Local address: %s", c.localAddr)
	c.log.Info("Server address: %s", c.serverAddr)
	c.log.Info("Fragmentation enabled: %v", c.cfg.Evasion.Fragmentation.Enabled)

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

	// Start loops
	c.mu.Lock()
	c.started = true
	c.mu.Unlock()

	c.wg.Add(3)
	go c.heartbeatLoop()
	go c.senderLoop()
	go c.statsLoop()

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
	// Create a session
	if c.session == nil || !c.session.Authenticated {
		// Only create new session if we don't have a valid one (or we are reconnecting)
		// Actually reconnect() creates the session. Initial start does too.
		// If we are here, c.session should be set by caller if it's a new session.
		if c.session == nil {
			c.session = c.sessionMgr.CreateSession(c.localAddr)
		}
	}

	// Build auth packet with token
	authData := []byte(c.cfg.AuthToken)

	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeAuth,
		Flags:     icmp.FlagAuth,
		SessionID: c.session.ID,
		SeqNum:    c.session.GetNextSeq(),
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

		srcIP, icmpType, icmpID, icmpSeq, rawPayload, err := c.socket.Receive()
		if err != nil {
			continue
		}

		if icmpType != 0 && (icmpType != 8 || (srcIP.Equal(c.localAddr) && !c.cfg.Spoof.Enabled)) {
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

		if tunnelPkt.SessionID == c.session.ID {
			if tunnelPkt.Type == icmp.TypeControl {
				if len(tunnelPkt.Data) > 0 && tunnelPkt.Data[0] == icmp.ControlAuthOK {
					c.session.Authenticated = true
					c.session.MarkReceived(tunnelPkt.SeqNum) // Advance sequence
					c.session.ProcessIncoming(tunnelPkt)   // Captures NAT info
					return nil
				}
				if len(tunnelPkt.Data) > 0 && tunnelPkt.Data[0] == icmp.ControlAuthFail {
					return fmt.Errorf("server rejected authentication")
				}
			}
		}
	}

	return fmt.Errorf("authentication timed out")
}

func (c *Client) handleConnect(protocol, destination string) (uint16, chan []byte, error) {
	streamID := icmp.GenerateStreamID()
	c.log.Debug("Generated streamID %d for connection to %s", streamID, destination)
	responseChan := make(chan []byte, 1024)
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
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeControl,
		SessionID: c.session.ID,
		SeqNum:    c.session.GetNextSeq(),
		Data:      controlData,
	}
	// Send connect request to server reliably
	if err := c.sendPacketReliable(pkt, 2*time.Second, 5); err != nil {
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
	case <-time.After(10 * time.Second):
		c.handleClose(streamID)
		return 0, nil, fmt.Errorf("connect timeout waiting for status")
	}
}

func (c *Client) handleData(streamID uint16, data []byte) error {
	c.aggMu.Lock()
	defer c.aggMu.Unlock()

	c.log.Debug("Aggregating %d bytes for stream %d (current agg: %d)", len(data), streamID, len(c.aggData))
	c.aggData = append(c.aggData, icmp.EncodeStreamData(streamID, data)...)

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

	// Compression
	compressed := data
	pktFlags := uint8(0)
	if len(data) > 128 {
		comp := c.session.Compress(data)
		if len(comp) < len(data) {
			compressed = comp
			pktFlags |= icmp.FlagCompressed
		}
	}
	
	pkt := &icmp.TunnelPacket{
		Type:      icmp.TypeData,
		Flags:     pktFlags,
		SessionID: c.session.ID,
		SeqNum:    c.session.GetNextSeq(),
		Data:      compressed,
	}

	c.session.RecordSent(pkt)
	c.log.Debug("Sending data packet: seq=%d, size=%d, flags=%x", pkt.SeqNum, len(pkt.Data), pkt.Flags)
	c.sendTunnelPacket(pkt)
}

func (c *Client) senderLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	sackTicker := time.NewTicker(100 * time.Millisecond) // Send ACKs frequently to keep window moving
	defer ticker.Stop()
	defer sackTicker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			retrans := c.session.GetRetransmissions()
			for _, p := range retrans {
				c.log.Debug("Retransmitting packet %d", p.SeqNum)
				c.sendTunnelPacket(p)
			}
		case <-sackTicker.C:
			// Send SACK/ACK to inform server of received packets
			if c.session != nil {
				sack := c.session.GenerateSACK()
				// Only send SACK if we have received something (AckedSeq > 0 or Blocks exist)
				// or if we just want to keep the connection alive/window moving.
				// For now, always send to ensure server knows our state.
				sackPkt := sack.EncodePacket(c.session.ID)
				c.sendTunnelPacket(sackPkt)
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

func (c *Client) handleClose(streamID uint16) {
	var needsSend bool

	c.streamsMu.Lock()
	if ch, ok := c.streams[streamID]; ok {
		close(ch)
		delete(c.streams, streamID)
		needsSend = true
	}
	c.streamsMu.Unlock()

	c.pendingMu.Lock()
	delete(c.pendingStreams, streamID)
	c.pendingMu.Unlock()

	// Send close packet to server OUTSIDE of streamsMu lock to avoid deadlock.
	// sendPacketReliable blocks waiting for ACK, and the receive loop needs
	// streamsMu.RLock() to dispatch incoming packets.
	if needsSend {
		closePkt := &icmp.TunnelPacket{
			Type:      icmp.TypeControl,
			SessionID: c.session.ID,
			SeqNum:    c.session.GetNextSeq(),
			Data:      icmp.EncodeControlMessage(icmp.ControlClose, streamID),
		}

		select {
		case <-c.done:
			// If already stopping, just send it best-effort once
			c.sendTunnelPacket(closePkt)
		default:
			c.sendPacketReliable(closePkt, 2*time.Second, 3)
		}
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

func (c *Client) sendTunnelPacket(pkt *icmp.TunnelPacket) error {
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
		// Use stable outbound ICMP flow
		icmpID := c.session.OutboundICMPID
		icmpSeq := c.session.GetNextICMPSeq()
		if err := c.sendICMP(p, icmpID, icmpSeq); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) sendICMP(payload []byte, icmpID, icmpSeq uint16) error {
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
	return c.socket.SendEcho(c.localAddr, c.serverAddr, icmpID, icmpSeq, payload)
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

		srcIP, icmpType, icmpID, icmpSeq, rawPayload, err := c.socket.Receive()
		if err != nil {
			// ... (existing error handling)
			continue
		}

		// Client only cares about Echo Reply (0) or Echo Request (8) if relayed
		// For NAT traversal, we might receive Echo Request (8) from the server
		// if it's echoing our packets back.
		if icmpType != 0 && (icmpType != 8 || (srcIP.Equal(c.localAddr) && !c.cfg.Spoof.Enabled)) {
			continue
		}

		c.log.Debug("Received ICMP type %d from %s, len %d", icmpType, srcIP, len(rawPayload))

		// Handle fragmentation if enabled
		var reassembledData []byte
		if c.cfg.Evasion.Fragmentation.Enabled {
			data, complete, err := fragBuf.Add(rawPayload)
			if err == nil {
				if !complete {
					continue // Waiting for more fragments
				}
				reassembledData = data
			} else {
				// Not a fragment, use direct payload
				reassembledData = rawPayload
			}
		} else {
			reassembledData = rawPayload
		}

		// Apply other evasion reversal (Padding, Resizing)
		processedData, err := c.evasion.Unapply([][]byte{reassembledData})
		if err == nil {
			reassembledData = processedData
		} else {
			c.log.Debug("Evasion Unapply failed: %v", err)
		}

		decryptedPayload, err := c.encryptor.Decrypt(reassembledData)
		if err != nil {
			continue
		}

		tunnelPkt, err := icmp.DecodeTunnelPacket(decryptedPayload)
		if err != nil {
			continue
		}
		
		tunnelPkt.ICMPID = icmpID
		tunnelPkt.ICMPSeq = icmpSeq

		if tunnelPkt.SessionID != c.session.ID {
			continue
		}

		c.log.Debug("Received tunnel pkt: Type=%d, Seq=%d, Len=%d", tunnelPkt.Type, tunnelPkt.SeqNum, len(tunnelPkt.Data))
		if tunnelPkt.Type == icmp.TypeControl {
			subtype, streamID, _ := icmp.DecodeControlMessage(tunnelPkt.Data)
			c.log.Debug("Control packet: subtype=%d, streamID=%d", subtype, streamID)
		}

		c.lastServerActivity = time.Now()

		// Decompression
		if (tunnelPkt.Flags & icmp.FlagCompressed) != 0 {
			decomp, err := c.session.Decompress(tunnelPkt.Data)
			if err == nil {
				tunnelPkt.Data = decomp
			}
		}

		// Check for ControlAuthFail immediately (bypassing sequence check)
		if tunnelPkt.Type == icmp.TypeControl {
			subtype, _, _ := icmp.DecodeControlMessage(tunnelPkt.Data)
			if subtype == icmp.ControlAuthFail {
				c.log.Warn("Received AuthFail from server, triggering reconnect")
				select {
				case c.authCh <- fmt.Errorf("server rejected authentication"):
				default:
				}
				c.abortPending(fmt.Errorf("server rejected authentication"))
				c.triggerReconnect()
				continue
			}
		}

		// Reliability layer: sequencing and reordering
		pkts := c.session.ProcessIncoming(tunnelPkt)
		if pkts == nil && c.session.IsDuplicate(tunnelPkt.SeqNum) && tunnelPkt.Type == icmp.TypeControl {
			// Re-acknowledge duplicate control packet to stop server retransmitting
			subtype, _, _ := icmp.DecodeControlMessage(tunnelPkt.Data)
			if subtype != icmp.ControlACK && subtype != icmp.ControlSACK {
				ackPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: c.session.ID,
					SeqNum:    c.session.GetNextSeq(),
					Data:      icmp.EncodeControlMessage(icmp.ControlACK, tunnelPkt.SeqNum),
				}
				c.sendTunnelPacket(ackPkt)
			}
		}
		for _, p := range pkts {
			switch p.Type {
			case icmp.TypeData:
				entries, err := icmp.DecodeAllStreamData(p.Data)
				if err != nil {
					continue
				}
				c.streamsMu.RLock()
				for _, entry := range entries {
					if ch, ok := c.streams[entry.StreamID]; ok {
						select {
						case ch <- entry.Data:
						default:
							// Drop if buffer full to avoid blocking the whole tunnel
						}
					}
				}
				c.streamsMu.RUnlock()

			case icmp.TypeControl:
				subtype, streamID, err := icmp.DecodeControlMessage(p.Data)
				if err != nil {
					continue
				}

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

				case icmp.ControlHeartbeat:
					if len(p.Data) >= 9 {
						sentAt := int64(binary.BigEndian.Uint64(p.Data[1:9]))
						elapsed := time.Now().UnixNano() - sentAt
						c.session.UpdateRTT(time.Duration(elapsed))
					}
				case icmp.ControlACK:
					// For ControlACK, streamID field carries the original SeqNum being ACKed
					
					// Reliability layer: mark as acknowledged
					c.session.ProcessACK(streamID, nil)

					// Sync handling: notify any synchronous waiters
					c.pendingMu.Lock()
					if ch, ok := c.pendingAcks[streamID]; ok {
						ch <- nil
						delete(c.pendingAcks, streamID)
					}
					c.pendingMu.Unlock()

				case icmp.ControlSACK:
					sack, err := icmp.DecodeSACK(p.Data)
					if err == nil {
						c.session.ProcessACK(sack.AckedSeq, sack.Blocks)
					}
				
				case icmp.ControlAuthOK:
					c.session.Authenticated = true
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

				if subtype != icmp.ControlACK && subtype != icmp.ControlSACK {
					ackPkt := &icmp.TunnelPacket{
						Type:      icmp.TypeControl,
						SessionID: c.session.ID,
						SeqNum:    c.session.GetNextSeq(),
						Data:      icmp.EncodeControlMessage(icmp.ControlACK, p.SeqNum),
					}
					c.sendTunnelPacket(ackPkt)
				}
			}
		}
	}
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()
	heartbeatTicker := time.NewTicker(10 * time.Second)
	sackTicker := time.NewTicker(200 * time.Millisecond)
	defer heartbeatTicker.Stop()
	defer sackTicker.Stop()

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
			// Send heartbeat with timestamp
			now := time.Now().UnixNano()
			ts := make([]byte, 8)
			binary.BigEndian.PutUint64(ts, uint64(now))
			
			pkt := &icmp.TunnelPacket{
				Type:      icmp.TypeControl,
				SessionID: c.session.ID,
				SeqNum:    c.session.GetNextSeq(),
				Data:      append([]byte{icmp.ControlHeartbeat}, ts...),
			}
			if err := c.sendTunnelPacket(pkt); err != nil {
				c.log.Error("Heartbeat send failed: %v", err)
			}

			// Check for timeout
			if time.Since(c.lastServerActivity) > 30*time.Second {
				c.log.Warn("Tunnel timeout, attempting to reconnect...")
				c.triggerReconnect()
			}
		case <-sackTicker.C:
			// Send SACK
			if c.session == nil {
				continue
			}
			sack := c.session.GenerateSACK()
			if len(sack.Blocks) > 0 || sack.AckedSeq != c.session.NextSeqRecv - 1 {
				sackPkt := &icmp.TunnelPacket{
					Type:      icmp.TypeControl,
					SessionID: c.session.ID,
					SeqNum:    c.session.GetNextSeq(),
					Data:      icmp.EncodeSACK(sack),
				}
				c.sendTunnelPacket(sackPkt)
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
		
		// Create new session
		newSession := icmp.NewSessionManager(5 * time.Minute).CreateSession(c.serverAddr)
		newSession.AuthToken = c.cfg.AuthToken
		c.session = newSession

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
	// So len(payload) max is s.maxPacketSize - 8.
	room := c.cfg.ICMP.MaxPacketSize - 8

	// Subtract Evasion overhead
	room -= c.evasion.Overhead()

	// Subtract Encryption overhead
	room -= c.encryptor.Overhead()

	// Subtract Tunnel header (9) and Stream Data header (4)
	room -= icmp.TunnelHeaderSize
	room -= icmp.StreamDataHeaderSize

	if room < 64 {
		room = 64 // Minimum safety
	}
	c.log.Debug("Calculated max stream data size: %d", room)
	return room
}
