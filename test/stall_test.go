package test

import (
	"crypto/rand"
	"fmt"
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

// TestConnectionStall reproduces the issue where connections stall after a few minutes
// and "Data for unknown stream" errors appear.
func TestConnectionStall(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges for ICMP sockets")
	}

	// 1. Setup Configs
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	forwardListen := l.Addr().String()
	l.Close()

	// Target Echo Server
	targetAddr, stopTarget := StartEchoServer(t)
	defer stopTarget()

	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "1s",
			WriteTimeout:  "1s",
			MaxPacketSize: 1500,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{Enabled: false},
		Logging:    config.LoggingConfig{Level: "info", Output: "stdout"},
		AuthTokens: []string{"test-token"},
	}

	clientCfg := &config.ClientConfig{
		ServerAddr: "127.0.0.1",
		BindAddr:   "127.0.0.1",
		AuthToken:  "test-token",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "1s",
			WriteTimeout:  "1s",
			MaxPacketSize: 1500,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{Enabled: false},
		Logging:    config.LoggingConfig{Level: "info", Output: "stdout"},
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

	time.Sleep(1 * time.Second)

	// 4. Stress Test Levels
	levels := []struct {
		name        string
		concurrency int
		duration    time.Duration
	}{
		{"Low", 5, 10 * time.Second},
		{"Medium", 20, 20 * time.Second},
		{"High", 50, 30 * time.Second},
		{"Very High", 100, 60 * time.Second},
	}

	payload := make([]byte, 10240) // 10KB
	rand.Read(payload)

	for _, level := range levels {
		t.Run(level.name, func(t *testing.T) {
			t.Logf("Starting %s load test with %d concurrent connections for %v...", level.name, level.concurrency, level.duration)
			
			var wg sync.WaitGroup
			errors := make(chan error, level.concurrency)
			stopCh := make(chan struct{})

			// Timer to stop test
			time.AfterFunc(level.duration, func() {
				close(stopCh)
			})

			for i := 0; i < level.concurrency; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					
					// Each worker repeatedly opens/closes connections
					for {
						select {
						case <-stopCh:
							return
						default:
						}

						conn, err := net.Dial("tcp", forwardListen)
						if err != nil {
							select {
							case errors <- fmt.Errorf("Conn %d dial failed: %v", id, err):
							default:
							}
							return
						}
						
						conn.SetDeadline(time.Now().Add(5 * time.Second))

						if _, err := conn.Write(payload); err != nil {
							conn.Close()
							select {
							case errors <- fmt.Errorf("Conn %d write failed: %v", id, err):
							default:
							}
							return
						}

						resp := make([]byte, len(payload))
						if _, err := io.ReadFull(conn, resp); err != nil {
							conn.Close()
							select {
							case errors <- fmt.Errorf("Conn %d read failed: %v", id, err):
							default:
							}
							return
						}
						
						conn.Close()
						// Small sleep to allow some cleanup? Or hammer it?
						// Hammer it to trigger race.
					}
				}(i)
			}
			
			wg.Wait()
			close(errors)
			
			for err := range errors {
				t.Errorf("Error during %s load: %v", level.name, err)
				// Break after first error to avoid spam
				break
			}
		})
	}
}
