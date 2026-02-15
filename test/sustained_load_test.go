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

	"github.com/user/icmptunnel/config"
)

func TestSustainedRealWorldLoad(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// 1. Setup Environment
	duration := 5 * time.Minute // Reduced from 10m for default run, but still sustained
	if testing.Short() {
		duration = 1 * time.Minute
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	fwdAddr := l.Addr().String()
	l.Close()

	opts := TunnelOptions{
		AuthToken: "sustained-test-token",
		Transport: config.TransportConfig{
			WindowSize: 512,
		},
		Forwards: []config.ForwardConfig{
			{Listen: fwdAddr, Destination: targetAddr, Protocol: "tcp"},
		},
	}

	_, client, cleanup := setupTunnel(t, opts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	errCount := uint64(0)
	activeLongLived := int32(0)
	activeChurn := int32(0)

	// 2. Monitoring Goroutine
	metricDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		startAlloc, startGoro := getResourceStats()
		startTime := time.Now()

		fmt.Printf("\n%-10s | %-8s | %-10s | %-10s | %-8s | %-8s | %-6s\n", 
			"Elapsed", "Reconns", "TX Mbps", "RX Mbps", "Goro", "Mem MB", "Errors")
		fmt.Println("--------------------------------------------------------------------------------")

		var lastTx, lastRx uint64
		lastTime := startTime

		for {
			select {
			case <-ctx.Done():
				close(metricDone)
				return
			case now := <-ticker.C:
				reconns, txBytes, rxBytes, _, _ := client.GetStats()
				curAlloc, curGoro := getResourceStats()
				
				dt := now.Sub(lastTime).Seconds()
				txMbps := float64(txBytes-lastTx) * 8 / (1024 * 1024) / dt
				rxMbps := float64(rxBytes-lastRx) * 8 / (1024 * 1024) / dt
				
				fmt.Printf("%-10s | %-8d | %-10.2f | %-10.2f | %-8d | %-8.1f | %-6d\n",
					now.Sub(startTime).Truncate(time.Second),
					reconns,
					txMbps,
					rxMbps,
					curGoro,
					float64(curAlloc)/(1024*1024),
					atomic.LoadUint64(&errCount))

				lastTx, lastRx = txBytes, rxBytes
				lastTime = now

				if curGoro > startGoro + 1200 { // 150 streams * ~7-8 goroutines/stream
					t.Errorf("Resource Leak: Goroutines jumped from %d to %d", startGoro, curGoro)
				}
				if float64(curAlloc) > float64(startAlloc) + 256*1024*1024 { // Allow 256MB for 150 streams
					t.Errorf("Resource Leak: Memory growth exceeded 256MB")
				}
			}
		}
	}()

	// 3. Persistent "High Bandwidth" Stream (e.g. video/file streaming mock)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", fwdAddr)
		if err != nil {
			t.Errorf("Persistent stream dial failed: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 32768)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(buf); err != nil {
					atomic.AddUint64(&errCount, 1)
					return
				}
				if _, err := io.ReadFull(conn, buf); err != nil {
					atomic.AddUint64(&errCount, 1)
					return
				}
				// Aggressive streaming
			}
		}
	}()

	// 4. Long-Lived Sessions (50 parallel connections)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			atomic.AddInt32(&activeLongLived, 1)
			defer atomic.AddInt32(&activeLongLived, -1)

			var conn net.Conn
			var err error
			for retry := 0; retry < 5; retry++ {
				conn, err = net.DialTimeout("tcp", fwdAddr, 5*time.Second)
				if err == nil {
					break
				}
				time.Sleep(1 * time.Second)
			}
			if err != nil {
				atomic.AddUint64(&errCount, 1)
				t.Logf("Long-lived stream %d failed to dial: %v", id, err)
				return
			}
			defer conn.Close()
			time.Sleep(100 * time.Millisecond) // Stagger startup

			payload := []byte(fmt.Sprintf("long-lived-stream-%d-data", id))
			resp := make([]byte, len(payload))

			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := conn.Write(payload); err != nil {
						atomic.AddUint64(&errCount, 1)
						return
					}
					if _, err := io.ReadFull(conn, resp); err != nil {
						atomic.AddUint64(&errCount, 1)
						return
					}
				}
			}
		}(i)
	}

	// 5. High Churn Component (Rotating concurrent streams)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Keep ~100 churn streams alive at any time
				if atomic.LoadInt32(&activeChurn) < 100 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						atomic.AddInt32(&activeChurn, 1)
						defer atomic.AddInt32(&activeChurn, -1)

						conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
						if err != nil {
							atomic.AddUint64(&errCount, 1)
							return
						}
						defer conn.Close()
						
						// Short burst
						verifyEcho(t, conn, 1024)
						time.Sleep(time.Duration(2+idCount()%5) * time.Second)
					}()
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	<-metricDone

	finalErrors := atomic.LoadUint64(&errCount)
	if finalErrors > 100 { // Allow some transient failures over 10 mins of heavy churn
		t.Errorf("Too many errors during sustained load: %d", finalErrors)
	}
}

var idCounter uint64
func idCount() uint64 {
	return atomic.AddUint64(&idCounter, 1)
}
