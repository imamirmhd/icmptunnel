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
	"strings"
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
	pendingAcks    map[uint16]chan struct{}
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
		pendingAcks:    make(map[uint16]chan struct{}),
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
	for time.Now().Before(deadline) {
		_, _, _, _, rawPayload, err := c.socket.Receive()
		if err != nil {
			continue
		}

		// Handle fragmentation and evasion
		var reassembledData []byte
		if c.cfg.Evasion.Fragmentation.Enabled {
			processed, err := c.evasion.Unapply([][]byte{rawPayload})
			if err != nil {
				continue
			}
			reassembledData = processed
		} else {
			processed, err := c.evasion.Unapply([][]byte{rawPayload})
			if err != nil {
				continue
			}
			reassembledData = processed
		}

		decrypted, err := c.encryptor.Decrypt(reassembledData)
		if err != nil {
			continue
		}

		tunnelPkt, err := icmp.DecodeTunnelPacket(decrypted)
		if err != nil {
			continue
		}

		if tunnelPkt.SessionID == c.session.ID {
			if tunnelPkt.Type == icmp.TypeControl {
				if len(tunnelPkt.Data) > 0 && tunnelPkt.Data[0] == icmp.ControlAuthOK {
					c.session.Authenticated = true
					c.session.MarkReceived(tunnelPkt.SeqNum) // Advance sequence
					c.session.ProcessIncoming(tunnelPkt)   // Actually advance nextRecvSeq
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
	responseChan := make(chan []byte, 256)
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
	c.sendTunnelPacket(pkt)
}

func (c *Client) senderLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

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
	c.streamsMu.Lock()
	if ch, ok := c.streams[streamID]; ok {
		close(ch)
		delete(c.streams, streamID)

		// Inform server
		closePkt := &icmp.TunnelPacket{
			Type:      icmp.TypeControl,
			SessionID: c.session.ID,
			SeqNum:    c.session.GetNextSeq(),
			Data:      icmp.EncodeControlMessage(icmp.ControlClose, streamID),
		}
		c.sendPacketReliable(closePkt, 2*time.Second, 3)
	}
	c.streamsMu.Unlock()

	c.pendingMu.Lock()
	delete(c.pendingStreams, streamID)
	c.pendingMu.Unlock()
}

func (c *Client) sendPacketReliable(pkt *icmp.TunnelPacket, timeout time.Duration, maxRetries int) error {
	ackChan := make(chan struct{}, 1)
	
	for i := 0; i <= maxRetries; i++ {
		// New sequence number each time? 
		// Actually for reliability of a single logical command, we should use same SeqNum if it's the same packet.
		// Use SeqNum as key
		c.pendingMu.Lock()
		c.pendingAcks[pkt.SeqNum] = ackChan
		c.pendingMu.Unlock()

		if err := c.sendTunnelPacket(pkt); err != nil {
			return err
		}

		select {
		case <-ackChan:
			return nil
		case <-time.After(timeout):
			// retry
			c.log.Debug("Packet %d timeout, retry %d", pkt.SeqNum, i+1)
		}
	}

	c.pendingMu.Lock()
	delete(c.pendingAcks, pkt.SeqNum)
	c.pendingMu.Unlock()

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
		if err := c.sendICMP(p); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) sendICMP(payload []byte) error {
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
		return c.socket.SendEcho(c.serverAddr, relayIP, 0, 0, spoofedPayload)
	}

	return c.socket.SendEcho(c.localAddr, c.serverAddr, 0, 0, payload)
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

		_, _, _, _, rawPayload, err := c.socket.Receive()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "bad file descriptor") {
				return
			}
			continue
		}

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

		if tunnelPkt.SessionID != c.session.ID {
			continue
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
				go c.reconnect()
				continue
			}
		}

		// Reliability layer: sequencing and reordering
		pkts := c.session.ProcessIncoming(tunnelPkt)
		for _, p := range pkts {
			switch p.Type {
			case icmp.TypeData:
				streamID, data, err := icmp.DecodeStreamData(p.Data)
				if err != nil {
					continue
				}
				c.streamsMu.RLock()
				if ch, ok := c.streams[streamID]; ok {
					select {
					case ch <- data:
					default:
						c.log.Warn("Stream %d buffer full, dropping data", streamID)
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
					c.pendingMu.Lock()
					if ch, ok := c.pendingAcks[streamID]; ok {
						close(ch)
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
					// If we are running, trigger reconnect
					go c.reconnect()
				}
			}
		}
	}
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Start receiveLoop once
	c.wg.Add(1)
	go c.receiveLoop()

	// Initial activity
	c.lastServerActivity = time.Now()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
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

			// Send SACK
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


			// Check for timeout
			if time.Since(c.lastServerActivity) > 30*time.Second {
				c.log.Warn("Tunnel timeout, attempting to reconnect...")
				c.reconnect()
			}
		}
	}
}

func (c *Client) reconnect() {
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

		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
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

	// Subtract Tunnel header (9) and Stream Data header (2)
	room -= icmp.TunnelHeaderSize
	room -= 2 // StreamDataHeaderSize

	if room < 64 {
		room = 64 // Minimum safety
	}
	c.log.Debug("Calculated max stream data size: %d", room)
	return room
}
