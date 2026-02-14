// Package relay implements a lightweight ICMP relay server for spoofed traffic.
package relay

import (
	"net"
	"sync"
	"time"

	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/icmp"
	"github.com/user/icmptunnel/logger"
)

// Server is a lightweight relay that forwards ICMP packets.
// In spoofing mode, the client sends ICMP echo requests to the relay with a
// forged source IP (the main server's IP). The kernel or the relay echoes
// back to the forged source, which is the main server. The main server
// processes the packet and finds the real client IP embedded in the payload.
type Server struct {
	cfg       *config.RelayServerConfig
	socket    *icmp.Socket
	log       *logger.Logger
	rateLimit *rateLimiter
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewServer creates a new relay server.
func NewServer(cfg *config.RelayServerConfig) (*Server, error) {
	log := logger.Init(cfg.Logging.Level, cfg.Logging.Output).WithComponent("relay")

	sock, err := icmp.NewSocket(1472, 64, 5*time.Second, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, err
	}

	rl := newRateLimiter(cfg.RateLimit)

	return &Server{
		cfg:       cfg,
		socket:    sock,
		log:       log,
		rateLimit: rl,
		done:      make(chan struct{}),
	}, nil
}

// Start begins the relay server.
func (s *Server) Start() error {
	s.log.Info("Starting ICMP relay server on %s (rate limit: %d pps)", s.cfg.Listen, s.cfg.RateLimit)

	s.wg.Add(1)
	go s.receiveLoop()

	return nil
}

// Stop shuts down the relay server.
func (s *Server) Stop() {
	s.log.Info("Stopping relay server")
	close(s.done)
	s.socket.Close()
	s.wg.Wait()
}

// Wait blocks until the server is stopped.
func (s *Server) Wait() {
	c := make(chan struct{})
	<-c
}

func (s *Server) receiveLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		srcIP, icmpType, payload, err := s.socket.Receive()
		if err != nil {
			continue
		}

		// Only process echo requests
		if icmpType != 8 {
			continue
		}

		// Rate limiting
		if !s.rateLimit.allow(srcIP.String()) {
			continue
		}

		// Check source whitelist
		if len(s.cfg.AllowedSources) > 0 && !s.isAllowed(srcIP) {
			s.log.Debug("Blocked packet from non-whitelisted source: %s", srcIP)
			continue
		}

		s.log.Debug("Relaying ICMP from %s (%d bytes)", srcIP, len(payload))

		// The relay simply echoes back. Since the source IP is spoofed
		// (set to the main server's IP by the client), the echo reply
		// will be sent to the main server by the kernel.
		// We explicitly send an echo reply for better control.
		localIP := getLocalIP()
		if err := s.socket.SendReply(localIP, srcIP, payload); err != nil {
			s.log.Error("Failed to relay: %v", err)
		}
	}
}

func (s *Server) isAllowed(ip net.IP) bool {
	for _, allowed := range s.cfg.AllowedSources {
		if _, network, err := net.ParseCIDR(allowed); err == nil {
			if network.Contains(ip) {
				return true
			}
		} else if ip.String() == allowed {
			return true
		}
	}
	return false
}

// rateLimiter implements a simple per-source rate limiter.
type rateLimiter struct {
	limit   int
	counts  map[string]*tokenBucket
	mu      sync.Mutex
}

type tokenBucket struct {
	tokens    int
	lastReset time.Time
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{
		limit:  limit,
		counts: make(map[string]*tokenBucket),
	}
}

func (r *rateLimiter) allow(source string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, exists := r.counts[source]
	if !exists {
		r.counts[source] = &tokenBucket{tokens: r.limit - 1, lastReset: now}
		return true
	}

	// Reset every second
	if now.Sub(bucket.lastReset) > time.Second {
		bucket.tokens = r.limit - 1
		bucket.lastReset = now
		return true
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
