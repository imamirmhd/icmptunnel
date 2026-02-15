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

// TestStability500Users stimulates 500 concurrent connections to ensure stability
// and checks for any reconnect events in the client logs (via error reporting channel if possible,
// but here we just check for connection errors).
func TestStability500Users(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// 1. Setup Echo Server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	forwardListen := l.Addr().String()
	l.Close()
	
	// Reuse StartEchoServer from stall_test.go via copy or if in same package
	// Since we are adding this file to 'package test', and stall_test.go is 'package test' (if configured that way),
	// they should be able to share if we run them together.
	// But `go test ./test/stability_test.go` compiles only this file.
	// We will reimplement a simple echo server here to be safe and standalone.
	
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Target listen failed: %v", err)
	}
	targetAddr := targetListener.Addr().String()
	defer targetListener.Close()
	
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil { return }
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Configs - Using loosened timeouts as suspect
	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "5s", // Increased from 1s
			WriteTimeout:  "5s",
			MaxPacketSize: 1500,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{Enabled: false},
		Logging:    config.LoggingConfig{Level: "info", Output: "stdout"},
		AuthTokens: []string{"test-token-500"},
	}

	clientCfg := &config.ClientConfig{
		ServerAddr: "127.0.0.1",
		BindAddr:   "127.0.0.1",
		AuthToken:  "test-token-500",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "5s", // Increased from 1s
			WriteTimeout:  "5s",
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

	// 3. Start Infrastructure
	srv, err := tunnel.NewServer(serverCfg)
	if err != nil { t.Fatalf("NewServer: %v", err) }
	if err := srv.Start(); err != nil { t.Fatalf("Server Start: %v", err) }
	defer srv.Stop()
	
	time.Sleep(500 * time.Millisecond)

	cli, err := tunnel.NewClient(clientCfg)
	if err != nil { t.Fatalf("NewClient: %v", err) }
	if err := cli.Start(); err != nil { t.Fatalf("Client Start: %v", err) }
	defer cli.Stop()

	time.Sleep(1 * time.Second)

	// 4. Run 500 Concurrent Users
	concurrency := 500
	duration := 2 * time.Minute // "Keep them active for several minutes"
	
	t.Logf("Starting 500-user stability test for %v...", duration)

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)
	stopCh := make(chan struct{})

	time.AfterFunc(duration, func() { close(stopCh) })

	// Large payload to stress bandwidth and queues
	payload := make([]byte, 5000) 
	rand.Read(payload)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
				}

				// Each "user" opens a connection, sends data, reads it back.
				// To simulate "active for minutes", we can keep the connection open for a bit
				// or rapidly cycle. User said "open multiple streams", implying churn or concurrent streams.
				// Let's do short-lived connections to stress the stream setup/teardown too.
				
				conn, err := net.Dial("tcp", forwardListen)
				if err != nil {
					// Check if it's a temporary error or permanent failure
					select {
					case errCh <- fmt.Errorf("Dial %d: %v", id, err):
					default:
					}
					// Backoff slightly on error to avoid log spam if system is down
					time.Sleep(1 * time.Second)
					continue
				}
				
				// Set strict deadline? Or loose?
				// If we want NO disconnects, we expect the tunnel to carry traffic reasonably fast.
				// 10s deadline for 500 users sharing one tunnel on localhost might be tight but required for stability.
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				if _, err := conn.Write(payload); err != nil {
					conn.Close()
					select {
					case errCh <- fmt.Errorf("Write %d: %v", id, err):
					default:
					}
					continue
				}

				buf := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, buf); err != nil {
					conn.Close()
					select {
					case errCh <- fmt.Errorf("Read %d: %v", id, err):
					default:
					}
					continue
				}
				conn.Close()
				
				// Relax: Sleep random amount to vary load?
				// Or hammer? "System should remain stable under this sustained load" -> Hammer.
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	failureCount := 0
	for err := range errCh {
		failureCount++
		if failureCount <= 10 {
			t.Logf("Error: %v", err)
		}
	}
	
	if failureCount > 0 {
		t.Fatalf("Test failed with %d errors (disconnects/timeouts)", failureCount)
	}
	t.Log("Stability test passed with 0 errors.")
}
