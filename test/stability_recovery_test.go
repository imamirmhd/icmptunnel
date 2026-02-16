package test

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/tunnel"
)

func TestStabilityAndRecovery(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "stability-test-token",
	}

	// 1. Graceful Shutdown
	t.Run("GracefulShutdown", func(t *testing.T) {
		_, initialGoroutines := getResourceStats()

		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		
		// Run some traffic
		conn, _ := net.Dial("tcp", fwd)
		verifyEcho(t, conn, 1024)
		conn.Close()

		cleanup() // cli.Stop(), srv.Stop()

		// Allow some time for goroutines to exit
		time.Sleep(1 * time.Second)
		runtime.GC()
		
		_, finalGoroutines := getResourceStats()
		// We allow some overhead, but it shouldn't be significantly more.
		// Some system goroutines might have started.
		if finalGoroutines > initialGoroutines+10 {
			t.Errorf("Potential goroutine leak: initial=%d, final=%d", initialGoroutines, finalGoroutines)
		}
	})

	// 2. Partial Stream Interruption
	t.Run("PartialStreamInterruption", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		conn1, _ := net.Dial("tcp", fwd)
		conn2, _ := net.Dial("tcp", fwd)
		
		verifyEcho(t, conn1, 64)
		verifyEcho(t, conn2, 64)

		// Close conn1
		conn1.Close()
		time.Sleep(200 * time.Millisecond)

		// conn2 should still work
		verifyEcho(t, conn2, 64)
		conn2.Close()
	})

	// 3. Server Restart
	t.Run("ServerRestart", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		// Server Config
		serverCfg := &config.ServerConfig{
			Listen: "127.0.0.1",
			AuthTokens: []string{opts.AuthToken},
			ICMP: config.ICMPConfig{ReadTimeout: "1s", WriteTimeout: "1s"},
		}

		srv, err := tunnel.NewServer(serverCfg)
		srv.Start()
		
		// Client Config
		clientCfg := &config.ClientConfig{
			ServerAddr: "127.0.0.1",
			AuthToken:  opts.AuthToken,
			Forwards:   fwdOpts.Forwards,
			ICMP: config.ICMPConfig{ReadTimeout: "1s", WriteTimeout: "1s"},
		}
		cli, _ := tunnel.NewClient(clientCfg)
		cli.Start()
		
		time.Sleep(1 * time.Second)
		
		// Initial check
		conn, err := net.Dial("tcp", fwd)
		if err != nil { t.Fatalf("Initial dial failed: %v", err) }
		verifyEcho(t, conn, 64)
		conn.Close()

		// Stop Server
		t.Log("Stopping server...")
		srv.Stop()
		time.Sleep(1 * time.Second)

		// Start Server again
		t.Log("Restarting server...")
		srv, _ = tunnel.NewServer(serverCfg)
		srv.Start()
		defer srv.Stop()
		defer cli.Stop()

		// Wait for client to reconnect (it should have a retry loop)
		t.Log("Waiting for client to reconnect...")
		time.Sleep(3 * time.Second)

		// Check if it works again
		conn, err = net.Dial("tcp", fwd)
		if err != nil {
			t.Fatalf("Dial after restart failed: %v", err)
		}
		defer conn.Close()
		verifyEcho(t, conn, 64)
	})

	// 4. Idle and Burst
	t.Run("IdleAndBurst", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		// Idle for 2 seconds
		time.Sleep(2 * time.Second)

		// Sudden burst
		const burst = 20
		done := make(chan bool, burst)
		for i := 0; i < burst; i++ {
			go func() {
				conn, err := net.Dial("tcp", fwd)
				if err != nil {
					done <- false
					return
				}
				defer conn.Close()
				verifyEcho(t, conn, 128)
				done <- true
			}()
		}

		for i := 0; i < burst; i++ {
			if !<-done {
				t.Error("Burst client failed")
			}
		}
	})
}
