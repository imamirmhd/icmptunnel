package test

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/user/icmptunnel/config"
)

func TestConcurrencyAndLoad(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "stress-test-token",
	}

	levels := []int{10, 50, 100}
	if testing.Short() {
		levels = []int{10}
	}

	for _, concurrency := range levels {
		t.Run(fmt.Sprintf("ConcurrentClients_%d", concurrency), func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			forwardListen := l.Addr().String()
			l.Close()

			fwdOpts := opts
			fwdOpts.Forwards = []config.ForwardConfig{
				{Listen: forwardListen, Destination: targetAddr, Protocol: "tcp"},
			}

			_, _, cleanup := setupTunnel(t, fwdOpts)
			defer cleanup()

			var wg sync.WaitGroup
			errCh := make(chan error, concurrency)

			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					conn, err := net.Dial("tcp", forwardListen)
					if err != nil {
						errCh <- fmt.Errorf("Client %d dial: %v", id, err)
						return
					}
					defer conn.Close()
					
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					verifyEcho(t, conn, 512)
				}(i)
			}

			wg.Wait()
			close(errCh)
			for err := range errCh {
				t.Error(err)
			}
		})
	}

	t.Run("StreamChurn", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		forwardListen := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: forwardListen, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		const goroutines = 5
		const iterations = 20
		var wg sync.WaitGroup

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(gid int) {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					conn, err := net.Dial("tcp", forwardListen)
					if err != nil {
						t.Errorf("G %d Iter %d dial: %v", gid, j, err)
						return
					}
					verifyEcho(t, conn, 128)
					conn.Close()
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("MixedWorkload", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		forwardListen := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: forwardListen, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		var wg sync.WaitGroup
		
		// 10 Short-lived
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, _ := net.Dial("tcp", forwardListen)
				if conn != nil {
					verifyEcho(t, conn, 64)
					conn.Close()
				}
			}()
		}

		// 2 Long-lived
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, _ := net.Dial("tcp", forwardListen)
				if conn != nil {
					defer conn.Close()
					for start := time.Now(); time.Since(start) < 5*time.Second; {
						verifyEcho(t, conn, 256)
						time.Sleep(500 * time.Millisecond)
					}
				}
			}()
		}

		wg.Wait()
	})
}
