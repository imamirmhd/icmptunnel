package test

import (
	"net"
	"os"
	"sync"
	"testing"

	"github.com/user/icmptunnel/config"
)

func TestRealWorldSimulation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "realworld-test-token",
	}

	// 1. Short-Lived Connections (Browser-like)
	t.Run("ShortLivedConnections", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()
		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		const count = 50
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.Dial("tcp", fwd)
				if err != nil { return }
				defer conn.Close()
				verifyEcho(t, conn, 128)
			}()
		}
		wg.Wait()
	})

	// 2. Mixed Payload Sizes
	t.Run("MixedPayloadSizes", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()
		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		conn, _ := net.Dial("tcp", fwd)
		defer conn.Close()

		sizes := []int{64, 1500, 500, 10000, 256}
		for _, sz := range sizes {
			verifyEcho(t, conn, sz)
		}
	})

	// 3. Concurrent Different Targets
	t.Run("ConcurrentDifferentTargets", func(t *testing.T) {
		target2, stop2 := setupEchoServer(t)
		defer stop2()

		l1, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd1 := l1.Addr().String()
		l1.Close()

		l2, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd2 := l2.Addr().String()
		l2.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd1, Destination: targetAddr, Protocol: "tcp"},
			{Listen: fwd2, Destination: target2, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			conn, _ := net.Dial("tcp", fwd1)
			if conn != nil {
				defer conn.Close()
				verifyEcho(t, conn, 100)
			}
		}()

		go func() {
			defer wg.Done()
			conn, _ := net.Dial("tcp", fwd2)
			if conn != nil {
				defer conn.Close()
				verifyEcho(t, conn, 200)
			}
		}()

		wg.Wait()
	})
}
