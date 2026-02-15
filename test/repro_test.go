package test

import (
	"crypto/rand"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/tunnel"
)

// StartEchoServer starts a simple TCP echo server and returns its address
func StartEchoServer(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	
	return l.Addr().String(), func() { l.Close() }
}

func TestHighConcurrency(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges for ICMP sockets")
	}

	// 1. Setup Configs
	// Find a free port for the Forwarder
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	forwardListen := l.Addr().String()
	l.Close()

	// Target Echo Server
	targetAddr, stopTarget := StartEchoServer(t)
	defer stopTarget()

	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		ICMP: config.ICMPConfig{
			ReadTimeout:  "100ms", // Fast timeout for test
			WriteTimeout: "100ms",
			MaxPacketSize: 1500,
			TTL: 64,
		},
		Encryption: config.EncryptionConfig{Enabled: false},
		Logging:    config.LoggingConfig{Level: "debug", Output: "stdout"},
		AuthTokens: []string{"test-token"},
	}

	clientCfg := &config.ClientConfig{
		ServerAddr: "127.0.0.1",
		BindAddr:   "127.0.0.1",
		AuthToken:  "test-token",
		ICMP: config.ICMPConfig{
			ReadTimeout:  "100ms",
			WriteTimeout: "100ms",
			MaxPacketSize: 1500,
			TTL: 64,
		},
		Encryption: config.EncryptionConfig{Enabled: false},
		Logging:    config.LoggingConfig{Level: "debug", Output: "stdout"},
		Forwards: []config.ForwardConfig{
			{
				Listen:      forwardListen,
				Destination: targetAddr,
				Protocol:    "tcp",
			},
		},
	}

	// 2. Start Server
	srv, err := tunnel.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	// Give server a moment to bind
	time.Sleep(500 * time.Millisecond)

	// 3. Start Client
	cli, err := tunnel.NewClient(clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}
	defer cli.Stop()

	// Give client a moment to authenticate and start forwarder
	time.Sleep(1 * time.Second)

	// 4. Stress Test
	concurrency := 50
	packetsPerConn := 10
	var wg sync.WaitGroup
	
	t.Logf("Starting stress test with %d concurrent connections...", concurrency)
	
	start := time.Now()
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", forwardListen)
			if err != nil {
				t.Errorf("Conn %d dial failed: %v", id, err)
				return
			}
			defer conn.Close()
			
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			
			buf := make([]byte, 1024)
			rand.Read(buf)
			
			for j := 0; j < packetsPerConn; j++ {
				// Send
				if _, err := conn.Write(buf); err != nil {
					t.Errorf("Conn %d write failed: %v", id, err)
					return
				}
				
				// Recv
				resp := make([]byte, len(buf))
				if _, err := io.ReadFull(conn, resp); err != nil {
					t.Errorf("Conn %d read failed: %v", id, err)
					return
				}
			}
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	t.Logf("Stress test completed in %v", duration)
}
