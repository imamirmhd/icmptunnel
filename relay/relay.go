// Package relay implements a lightweight ICMP relay server for spoofing.
package relay

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/icmp"
	"github.com/imamirmhd/icmptunnel/logger"
)

// Server relays ICMP packets between clients and tunnel servers.
type Server struct {
	cfg     *config.RelayServerConfig
	socket  *icmp.Socket
	log     *logger.Logger

	// Rate limiting per source
	rates   map[string]*rateLimiter
	ratesMu sync.Mutex
	maxPPS  int

	// Allowed sources
	allowed map[string]bool

	done chan struct{}
	wg   sync.WaitGroup

	// Stats
	statsRelayed uint64
	statsDropped uint64
}

type rateLimiter struct {
	count    int64
	lastReset time.Time
}

// NewServer creates a new relay server.
func NewServer(cfg *config.RelayServerConfig) (*Server, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("relay")

	sock, err := icmp.NewSocket(1472, 16, 5*time.Second, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("creating socket: %w", err)
	}

	if err := sock.Bind(cfg.Listen); err != nil {
		sock.Close()
		return nil, fmt.Errorf("binding: %w", err)
	}

	allowed := make(map[string]bool)
	for _, src := range cfg.AllowedSources {
		allowed[src] = true
	}

	return &Server{
		cfg:     cfg,
		socket:  sock,
		log:     log,
		rates:   make(map[string]*rateLimiter),
		maxPPS:  cfg.RateLimit,
		allowed: allowed,
		done:    make(chan struct{}),
	}, nil
}

// Start begins relaying packets.
func (s *Server) Start() error {
	s.log.Info("Relay server started on %s (rate limit: %d pps)", s.cfg.Listen, s.maxPPS)

	s.wg.Add(1)
	go s.relayLoop()

	s.wg.Add(1)
	go s.statsLoop()

	return nil
}

// Stop shuts down the relay server.
func (s *Server) Stop() {
	close(s.done)
	s.socket.Close()
	s.wg.Wait()
	s.log.Info("Relay server stopped")
}

func (s *Server) relayLoop() {
	defer s.wg.Done()

	s.socket.SetReadDeadline(200 * time.Millisecond)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		srcIP, _, _, _, payload, rawBuf, err := s.socket.Receive()
		if err != nil {
			if rawBuf != nil {
				icmp.ReleaseBuffer(rawBuf)
			}
			continue
		}

		srcStr := srcIP.String()

		// Check allowed sources (if configured)
		if len(s.allowed) > 0 && !s.allowed[srcStr] {
			icmp.ReleaseBuffer(rawBuf)
			atomic.AddUint64(&s.statsDropped, 1)
			continue
		}

		// Rate limiting
		if !s.checkRate(srcStr) {
			icmp.ReleaseBuffer(rawBuf)
			atomic.AddUint64(&s.statsDropped, 1)
			continue
		}

		// Extract spoof header to find real destination
		if len(payload) < icmp.SpoofHeaderSize {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		spoofHdr, _, err := icmp.ExtractSpoofHeader(payload)
		if err != nil {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		// Forward the entire packet (including spoof header) to the tunnel server
		dstIP := spoofHdr.RelayIP
		if dstIP == nil {
			icmp.ReleaseBuffer(rawBuf)
			continue
		}

		localIP := getLocalIP()
		if sendErr := s.socket.Send(localIP, dstIP, 0, 0, payload); sendErr != nil {
			s.log.Debug("Relay forward failed: %v", sendErr)
		} else {
			atomic.AddUint64(&s.statsRelayed, 1)
		}

		icmp.ReleaseBuffer(rawBuf)
	}
}

func (s *Server) checkRate(src string) bool {
	s.ratesMu.Lock()
	defer s.ratesMu.Unlock()

	rl, ok := s.rates[src]
	if !ok {
		s.rates[src] = &rateLimiter{count: 1, lastReset: time.Now()}
		return true
	}

	if time.Since(rl.lastReset) > time.Second {
		rl.count = 1
		rl.lastReset = time.Now()
		return true
	}

	if rl.count >= int64(s.maxPPS) {
		return false
	}

	rl.count++
	return true
}

func (s *Server) statsLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			relayed := atomic.LoadUint64(&s.statsRelayed)
			dropped := atomic.LoadUint64(&s.statsDropped)
			s.log.Info("[RELAY STATS] relayed=%d dropped=%d", relayed, dropped)
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
