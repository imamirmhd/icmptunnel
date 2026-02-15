package test

import (
	"crypto/rand"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/icmp"
)

func TestSecurityAndAbuse(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "security-test-token",
	}

	// 1. Malformed Packets
	t.Run("MalformedPackets", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()
		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		// Send garbage to the ICMP socket manually
		sock, _ := icmp.NewSocket(1500, 64, time.Second, time.Second)
		defer sock.Close()

		garbage := make([]byte, 100)
		rand.Read(garbage)
		
		// Send some Echo Requests with garbage payload
		localIP := net.ParseIP("127.0.0.1")
		for i := 0; i < 5; i++ {
			sock.SendEcho(localIP, localIP, 1234, uint16(i), garbage)
		}

		// Verify tunnel still works
		conn, _ := net.Dial("tcp", fwd)
		if conn != nil {
			verifyEcho(t, conn, 64)
			conn.Close()
		}
	})

	// 2. Oversized Frame
	t.Run("OversizedFrame", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()
		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		conn, _ := net.Dial("tcp", fwd)
		if conn != nil {
			defer conn.Close()
			// Send 60KB (large for ICMP payload)
			verifyEcho(t, conn, 60000)
		}
	})

	// 3. Connection Flood
	t.Run("ConnectionFlood", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()
		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{{Listen: fwd, Destination: targetAddr, Protocol: "tcp"}}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		const flood = 100
		for i := 0; i < flood; i++ {
			conn, err := net.DialTimeout("tcp", fwd, 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}

		// Verify it still works
		conn, err := net.Dial("tcp", fwd)
		if err != nil {
			t.Fatalf("Dial after flood failed: %v", err)
		}
		verifyEcho(t, conn, 64)
		conn.Close()
	})

	// 4. SOCKS5 Abuse
	t.Run("SOCKS5_Unauthorized", func(t *testing.T) {
		socksAddr := "127.0.0.1:5055"
		s5Opts := opts
		s5Opts.Socks5 = []config.Socks5Config{
			{Listen: socksAddr, Username: "user", Password: "pass"},
		}

		_, _, cleanup := setupTunnel(t, s5Opts)
		defer cleanup()

		// Try without auth
		conn, _ := net.Dial("tcp", socksAddr)
		if conn != nil {
			defer conn.Close()
			// Send method negotiation: SOCKS5, 1 method, NO AUTH
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			io.ReadFull(conn, resp)
			if resp[1] == 0x00 {
				t.Error("SOCKS5 accepted NO AUTH when credentials are required")
			}
		}

		// Try with wrong password
		conn2, _ := net.Dial("tcp", socksAddr)
		if conn2 != nil {
			defer conn2.Close()
			conn2.Write([]byte{0x05, 0x01, 0x02}) // Method 02: User/Pass
			resp := make([]byte, 2)
			io.ReadFull(conn2, resp)
			if resp[1] == 0x02 {
				// Handshake ok, now send wrong creds
				conn2.Write([]byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x05, 'w', 'r', 'o', 'n', 'g'})
				io.ReadFull(conn2, resp)
				if resp[1] == 0x00 {
					t.Error("SOCKS5 accepted wrong credentials")
				}
			}
		}
	})
}
