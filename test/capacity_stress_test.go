package test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/tunnel"
)

func TestAbsoluteCapacityStress(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// 1. Controlled Environment Setup
	numClients := 3
	streamsPerClient := 20
	rampUpDelay := 10 * time.Second
	testDuration := 5 * time.Minute
	if testing.Short() {
		numClients = 2
		streamsPerClient = 5
		testDuration = 1 * time.Minute
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	// Server setup
	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "500ms",
			WriteTimeout:  "500ms",
			MaxPacketSize: 1472,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{Enabled: false}, // Focus on throughput/concurrency first
		AuthTokens: []string{"capacity-token"},
		Logging:    config.LoggingConfig{Level: "warn", Output: "stdout"},
		Transport: config.TransportConfig{
			WindowSize: 2048, // Aggressive window for high capacity
			MaxStreams: 100,  // Efficiently bound resources
		},
	}
	server, err := tunnel.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	var wg sync.WaitGroup
	errCount := uint64(0)
	totalTxBytes := uint64(0)
	totalRxBytes := uint64(0)

	// 2. Resource & Metric Monitoring
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		startAlloc, startGoro := getResourceStats()
		startTime := time.Now()

		fmt.Printf("\n%-10s | %-8s | %-10s | %-10s | %-8s | %-8s | %-6s\n",
			"Elapsed", "Clients", "TX Mbps", "RX Mbps", "Goro", "Mem MB", "Errors")
		fmt.Println("--------------------------------------------------------------------------------")

		var lastTx, lastRx uint64
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				curTx := atomic.LoadUint64(&totalTxBytes)
				curRx := atomic.LoadUint64(&totalRxBytes)
				curAlloc, curGoro := getResourceStats()

				dt := 10.0
				txMbps := float64(curTx-lastTx) * 8 / (1024 * 1024) / dt
				rxMbps := float64(curRx-lastRx) * 8 / (1024 * 1024) / dt

				fmt.Printf("%-10s | %-8d | %-10.2f | %-10.2f | %-8d | %-8.1f | %-6d\n",
					now.Sub(startTime).Truncate(time.Second),
					numClients,
					txMbps,
					rxMbps,
					curGoro,
					float64(curAlloc)/(1024*1024),
					atomic.LoadUint64(&errCount))

				lastTx, lastRx = curTx, curRx

				// Sanity check for runaway leaks
				if curGoro > startGoro + 2500 {
					t.Errorf("Potential Goroutine Leak: %d (Baseline: %d)", curGoro, startGoro)
				}
				if float64(curAlloc) > float64(startAlloc) + 512*1024*1024 {
					t.Errorf("Potential Memory Leak: %d MB (Baseline: %d MB)", int(float64(curAlloc)/(1024*1024)), int(float64(startAlloc)/(1024*1024)))
				}
			}
		}
	}()

	// 3. Independent Multi-Client Simulation
	for cID := 0; cID < numClients; cID++ {
		time.Sleep(rampUpDelay) // Staggered client join
		wg.Add(1)
		go func(clientId int) {
			defer wg.Done()
			
			// Each client needs a unique forwarder port to avoid port conflicts on 127.0.0.1
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			fwdAddr := l.Addr().String()
			l.Close()

			clientCfg := &config.ClientConfig{
				ServerAddr: "127.0.0.1",
				BindAddr:   "127.0.0.1", 
				AuthToken:  "capacity-token",
				ICMP: config.ICMPConfig{
					ReadTimeout: "500ms", WriteTimeout: "500ms", MaxPacketSize: 1472, TTL: 64,
				},
				Logging: config.LoggingConfig{Level: "warn", Output: "stdout"},
				Forwards: []config.ForwardConfig{
					{Listen: fwdAddr, Destination: targetAddr, Protocol: "tcp"},
				},
				Transport: config.TransportConfig{
					WindowSize: 1024,
				},
			}

			client, err := tunnel.NewClient(clientCfg)
			if err != nil {
				atomic.AddUint64(&errCount, 1)
				return
			}
			if err := client.Start(); err != nil {
				atomic.AddUint64(&errCount, 1)
				return
			}
			defer client.Stop()

			// Launch Streams for this client
			var clientWg sync.WaitGroup
			for sID := 0; sID < streamsPerClient; sID++ {
				clientWg.Add(1)
				go func(streamId int) {
					defer clientWg.Done()
					
					// Mix of long-lived and churny streams
					isChurny := (streamId % 5) == 0 
					
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}

						conn, err := net.DialTimeout("tcp", fwdAddr, 10*time.Second)
						if err != nil {
							atomic.AddUint64(&errCount, 1)
							time.Sleep(1 * time.Second)
							continue
						}

						// Continuous data flow
						buf := make([]byte, 16384)
						dataDone := false
						
						transferCount := 0
						maxTransfers := 100
						if isChurny {
							maxTransfers = 5 + (streamId % 10)
						}

						for !dataDone {
							select {
							case <-ctx.Done():
								conn.Close()
								return
							default:
							}

							conn.SetDeadline(time.Now().Add(5 * time.Second))
							n, err := conn.Write(buf)
							if err != nil {
								atomic.AddUint64(&errCount, 1)
								dataDone = true
								break
							}
							atomic.AddUint64(&totalTxBytes, uint64(n))

							rn, err := io.ReadFull(conn, buf)
							if err != nil {
								atomic.AddUint64(&errCount, 1)
								dataDone = true
								break
							}
							atomic.AddUint64(&totalRxBytes, uint64(rn))

							transferCount++
							if isChurny && transferCount >= maxTransfers {
								dataDone = true
							}
							
							if !isChurny {
								time.Sleep(10 * time.Millisecond) // Slight pacing for long-lived
							}
						}
						conn.Close()
						if !isChurny {
							break // Long-lived is done if it ever breaks loop (e.g. error)
						}
						time.Sleep(100 * time.Millisecond) // Churn delay
					}
				}(sID)
				time.Sleep(50 * time.Millisecond) // Stagger stream startup
			}
			clientWg.Wait()
		}(cID)
	}

	wg.Wait()
	
	finalErrors := atomic.LoadUint64(&errCount)
	t.Logf("Final Capacity Stats: TX=%dMB, RX=%dMB, Errors=%d", 
		atomic.LoadUint64(&totalTxBytes)/(1024*1024), 
		atomic.LoadUint64(&totalRxBytes)/(1024*1024), 
		finalErrors)
}
