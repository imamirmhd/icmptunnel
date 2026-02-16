package test

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
)

func TestPerformance(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "perf-test-token",
	}

	// 1. Throughput Saturation
	t.Run("Throughput", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		conn, _ := net.Dial("tcp", fwd)
		defer conn.Close()

		// Send as much as possible for 5 seconds
		duration := 5 * time.Second
		payload := make([]byte, 32768)
		var bytesSent uint64
		
		stop := make(chan struct{})
		time.AfterFunc(duration, func() { close(stop) })

		go func() {
			for {
				select {
				case <-stop: return
				default:
					n, err := conn.Write(payload)
					if err != nil { return }
					atomic.AddUint64(&bytesSent, uint64(n))
				}
			}
		}()

		// Discard replies
		discarded := make([]byte, 32768)
		for {
			select {
			case <-stop: goto done
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				conn.Read(discarded)
			}
		}
	done:
		mbps := float64(atomic.LoadUint64(&bytesSent)) * 8 / 1024 / 1024 / duration.Seconds()
		t.Logf("Throughput: %.2f Mbps", mbps)
	})

	// 2. Latency Under Load
	t.Run("LatencyUnderLoad", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		// Background load
		stopLoad := make(chan struct{})
		go func() {
			conn, _ := net.Dial("tcp", fwd)
			if conn != nil {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					select {
					case <-stopLoad: return
					default:
						conn.Write(buf)
						io.ReadFull(conn, make([]byte, 1024))
					}
				}
			}
		}()
		defer close(stopLoad)

		// Measure latency
		conn, _ := net.Dial("tcp", fwd)
		defer conn.Close()
		
		var totalRTT time.Duration
		const count = 10
		for i := 0; i < count; i++ {
			start := time.Now()
			verifyEcho(t, conn, 64)
			totalRTT += time.Since(start)
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("Average Latency under load: %v", totalRTT/time.Duration(count))
	})

	// 3. Size Matrix
	sizes := []int{64, 1400, 10000}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("PayloadSize_%d", size), func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			fwd := l.Addr().String()
			l.Close()

			fwdOpts := opts
			fwdOpts.Forwards = []config.ForwardConfig{
				{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
			}

			_, _, cleanup := setupTunnel(t, fwdOpts)
			defer cleanup()

			conn, _ := net.Dial("tcp", fwd)
			defer conn.Close()
			verifyEcho(t, conn, size)
		})
	}
}
