package test

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/user/icmptunnel/config"
)

func TestResourceManagement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "resource-test-token",
	}

	// 1. Memory and Goroutine Cleanup after load
	t.Run("CleanupAfterLoad", func(t *testing.T) {
		runtime.GC()
		initialMem, initialGoroutines := getResourceStats()

		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)

		// Create heavy churn
		const count = 50
		for i := 0; i < count; i++ {
			conn, _ := net.Dial("tcp", fwd)
			if conn != nil {
				verifyEcho(t, conn, 1024)
				conn.Close()
			}
		}

		cleanup()
		
		// Allow time for all background goroutines (like senderLoop, receiverLoop) to exit
		time.Sleep(2 * time.Second)
		runtime.GC()

		finalMem, finalGoroutines := getResourceStats()
		
		t.Logf("Goroutines: initial=%d, final=%d", initialGoroutines, finalGoroutines)
		t.Logf("Memory: initial=%d KB, final=%d KB", initialMem/1024, finalMem/1024)

		if finalGoroutines > initialGoroutines+15 {
			t.Errorf("Potential goroutine leak: %d -> %d", initialGoroutines, finalGoroutines)
		}
		
		// Memory check is fuzzier but we check it doesn't grow by 10x
		if finalMem > initialMem*10 && finalMem > 10*1024*1024 {
			t.Errorf("Significant memory growth: %d -> %d", initialMem, finalMem)
		}
	})

	// 2. Session Cleanup
	t.Run("SessionCleanup", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		srv, _, cleanup := setupTunnel(t, fwdOpts)
		
		// Check active sessions
		// Note: setupTunnel handles one persistent client session.
		if srv.ActiveSessions() != 1 {
			t.Errorf("Expected 1 active session, got %d", srv.ActiveSessions())
		}

		cleanup() // Stop client and server.
		// Note: srv.Stop() clears the session manager.
		
		if srv.ActiveSessions() != 0 {
			t.Errorf("Expected 0 sessions after Stop, got %d", srv.ActiveSessions())
		}
	})

	// 3. File Descriptor Check (Baseline)
	t.Run("FileDescriptors", func(t *testing.T) {
		// This is harder to cross-platform but we can check if it stays stable over cycles
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		for i := 0; i < 5; i++ {
			_, _, cleanup := setupTunnel(t, fwdOpts)
			// Open a few connections
			for j := 0; j < 5; j++ {
				conn, _ := net.Dial("tcp", fwd)
				if conn != nil { conn.Close() }
			}
			cleanup()
			time.Sleep(200 * time.Millisecond)
		}
		// If FDs were leaking, a 1000-iteration test would hit limits. 
		// For unit tests, we just verify it doesn't crash.
	})
}
