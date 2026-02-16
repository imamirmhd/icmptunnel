package test

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"strconv"

	"github.com/imamirmhd/icmptunnel/config"
)

func TestLongDurationStability(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "stability-test-token",
		Transport: config.TransportConfig{
			WindowSize: 512, // Larger window for sustained flow
		},
	}

	// 1. TestSustainedLongRunningLoad - 100 streams for 2 minutes
	t.Run("SustainedLoad_100streams_2min", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var wg sync.WaitGroup
		errCount := uint64(0)
		activeStreams := int32(0)

		streamCount := 100
		if len(os.Args) > 3 {
			// Very crude but enough for manual testing
			if val, err := strconv.Atoi(os.Args[len(os.Args)-1]); err == nil {
				streamCount = val
			}
		}

		for i := 0; i < streamCount; i++ {
			time.Sleep(200 * time.Millisecond) // Ramp up
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				atomic.AddInt32(&activeStreams, 1)
				defer atomic.AddInt32(&activeStreams, -1)

				conn, err := net.DialTimeout("tcp", fwd, 30*time.Second)
				if err != nil {
					count := atomic.AddUint64(&errCount, 1)
					if count <= 5 {
						t.Logf("Stream %d Dial error: %v", id, err)
					}
					return
				}
				defer conn.Close()

				// Jitter establishment to avoid total ICMP transport saturation
				time.Sleep(time.Duration(id%10) * 100 * time.Millisecond)

				buf := make([]byte, 1024)
				for {
					select {
					case <-ctx.Done():
						return
					default:
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := conn.Write([]byte("ping\n")); err != nil {
							count := atomic.AddUint64(&errCount, 1)
							if count <= 20 {
								t.Logf("Stream %d Write error: %v", id, err)
							}
							return
						}
						if _, err := io.ReadAtLeast(conn, buf, 5); err != nil {
							count := atomic.AddUint64(&errCount, 1)
							if count <= 30 {
								t.Logf("Stream %d Read error: %v", id, err)
							}
							return
						}
						time.Sleep(50 * time.Millisecond) // Sustained but not saturating
					}
				}
			}(i)
		}

		// Monitor loop
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				goto done
			case <-ticker.C:
				t.Logf("[Monitor] Active streams: %d, Errors so far: %d", atomic.LoadInt32(&activeStreams), atomic.LoadUint64(&errCount))
			}
		}
	done:
		wg.Wait()
		if atomic.LoadUint64(&errCount) > 30 { // Allow some transient drops under heavy load
			t.Errorf("Too many errors during sustained load: %d", atomic.LoadUint64(&errCount))
		}
	})

	// 2. TestContinuousDownloadWithChurn
	t.Run("ContinuousDownloadWithChurn", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		testCtx, testCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer testCancel()

		// A. Background Persistent "Download"
		dlDone := make(chan error, 1)
		go func() {
			conn, err := net.Dial("tcp", fwd)
			if err != nil {
				dlDone <- err
				return
			}
			defer conn.Close()
			
			const largeBufSize = 65536
			buf := make([]byte, largeBufSize)
			totalRead := 0
			for {
				select {
				case <-testCtx.Done():
					dlDone <- nil
					return
				default:
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := conn.Write(buf[:1024]); err != nil {
						dlDone <- err
						return
					}
					n, err := io.ReadAtLeast(conn, buf, 1024)
					if err != nil {
						dlDone <- err
						return
					}
					totalRead += n
				}
			}
		}()

		// B. Periodic Churn (Short-lived connections)
		var wg sync.WaitGroup
		churnErrCount := uint64(0)
		go func() {
			for {
				select {
				case <-testCtx.Done():
					return
				default:
					wg.Add(1)
					go func() {
						defer wg.Done()
						conn, err := net.DialTimeout("tcp", fwd, 5*time.Second)
						if err != nil {
							atomic.AddUint64(&churnErrCount, 1)
							return
						}
						defer conn.Close()
						verifyEcho(t, conn, 512)
						time.Sleep(100 * time.Millisecond)
					}()
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()

		select {
		case err := <-dlDone:
			if err != nil {
				t.Fatalf("Persistent download failed: %v", err)
			}
		case <-testCtx.Done():
		}
		
		wg.Wait()
		t.Logf("Churn error count: %d", atomic.LoadUint64(&churnErrCount))
	})
}

func TestStabilityMetrics(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "metrics-test-token",
		Transport: config.TransportConfig{
			WindowSize: 256,
		},
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	fwd := l.Addr().String()
	l.Close()

	fwdOpts := opts
	fwdOpts.Forwards = []config.ForwardConfig{
		{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
	}

	_, _, cleanup := setupTunnel(t, fwdOpts)
	defer cleanup()

	// Track metrics over 3 minutes
	duration := 3 * time.Minute
	startAlloc, startGoro := getResourceStats()
	startTime := time.Now()

	t.Logf("Starting metrics tracking. Initial: Alloc=%d, Goroutines=%d", startAlloc, startGoro)

	// Background constant load
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop: return
			default:
				conn, err := net.Dial("tcp", fwd)
				if err == nil {
					verifyEcho(t, conn, 1024)
					conn.Close()
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	endTime := time.Now().Add(duration)
	for time.Now().Before(endTime) {
		<-ticker.C
		curAlloc, curGoro := getResourceStats()
		elapsed := time.Since(startTime)
		t.Logf("[%v] curAlloc=%d (diff=%d), curGoro=%d", 
			elapsed.Truncate(time.Second), 
			curAlloc, int64(curAlloc)-int64(startAlloc),
			curGoro)
	}
	close(stop)

	finalAlloc, finalGoro := getResourceStats()
	t.Logf("Final metrics: Alloc=%d, Goroutines=%d", finalAlloc, finalGoro)
	
	// Sanity check: Should not have exploded (more than 100x increase in goroutines is likely a leak)
	if finalGoro > startGoro + 500 {
		t.Errorf("Potential goroutine leak detected: jumped from %d to %d", startGoro, finalGoro)
	}
}
