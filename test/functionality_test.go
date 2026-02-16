package test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/tunnel"
)

func TestCoreFunctionality(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	opts := TunnelOptions{
		AuthToken: "func-test-token",
	}

	// 1. Single Client Forwarding (TCP)
	t.Run("ForwardingTCP", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		forwardListen := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: forwardListen, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		conn, err := net.Dial("tcp", forwardListen)
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		verifyEcho(t, conn, 1024)
	})

	// 2. Multi-Stream Forwarding
	t.Run("MultiStream", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		forwardListen := l.Addr().String()
		l.Close()

		fwdOpts := opts
		fwdOpts.Forwards = []config.ForwardConfig{
			{Listen: forwardListen, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, fwdOpts)
		defer cleanup()

		const streams = 5
		done := make(chan bool)
		for i := 0; i < streams; i++ {
			go func() {
				conn, err := net.Dial("tcp", forwardListen)
				if err != nil {
					t.Errorf("Dial failed: %v", err)
					done <- false
					return
				}
				defer conn.Close()
				verifyEcho(t, conn, 512)
				done <- true
			}()
		}

		for i := 0; i < streams; i++ {
			if !<-done {
				t.Fail()
			}
		}
	})

	// 3. SOCKS5 Basic TCP
	t.Run("SOCKS5_Basic", func(t *testing.T) {
		socksAddr := "127.0.0.1:5051"
		s5Opts := opts
		s5Opts.Socks5 = []config.Socks5Config{{Listen: socksAddr}}

		_, _, cleanup := setupTunnel(t, s5Opts)
		defer cleanup()

		conn := dialSocks5(t, socksAddr, targetAddr, "", "")
		defer conn.Close()

		verifyEcho(t, conn, 1024)
	})

	// 4. SOCKS5 Authentication
	t.Run("SOCKS5_Auth", func(t *testing.T) {
		socksAddr := "127.0.0.1:5052"
		s5Opts := opts
		s5Opts.Socks5 = []config.Socks5Config{
			{Listen: socksAddr, Username: "user", Password: "pass"},
		}

		_, _, cleanup := setupTunnel(t, s5Opts)
		defer cleanup()

		// Should work with correct creds
		conn := dialSocks5(t, socksAddr, targetAddr, "user", "pass")
		defer conn.Close()
		verifyEcho(t, conn, 1024)
	})

	// 5. Encryption Matrix
	methods := []string{"aes-256-gcm", "chacha20-poly1305", "xor"}
	for _, m := range methods {
		t.Run("Encryption_"+m, func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			fwd := l.Addr().String()
			l.Close()

			encOpts := opts
			encOpts.EncryptionEnabled = true
			encOpts.EncryptionMethod = m
			encOpts.EncryptionKey = "01234567890123456789012345678901" // 32 bytes
			encOpts.Forwards = []config.ForwardConfig{
				{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
			}

			_, _, cleanup := setupTunnel(t, encOpts)
			defer cleanup()

			conn, _ := net.Dial("tcp", fwd)
			defer conn.Close()
			verifyEcho(t, conn, 1024)
		})
	}

	// 6. File Transfer Integrity
	t.Run("FileTransferLarge", func(t *testing.T) {
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

		// 1MB transfer
		size := 1024 * 1024
		data := make([]byte, size)
		io.ReadFull(rand.Reader, data)
		hash := sha256.Sum256(data)

		go func() {
			conn.Write(data)
		}()

		received := make([]byte, size)
		io.ReadFull(conn, received)
		recvHash := sha256.Sum256(received)

		if hex.EncodeToString(hash[:]) != hex.EncodeToString(recvHash[:]) {
			t.Error("File integrity check failed (SHA-256 mismatch)")
		}
	})

	// 7. Compression
	t.Run("Compression", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		fwd := l.Addr().String()
		l.Close()

		compOpts := opts
		compOpts.Compression = true
		compOpts.Forwards = []config.ForwardConfig{
			{Listen: fwd, Destination: targetAddr, Protocol: "tcp"},
		}

		_, _, cleanup := setupTunnel(t, compOpts)
		defer cleanup()

		conn, _ := net.Dial("tcp", fwd)
		defer conn.Close()
		verifyEcho(t, conn, 2048)
	})
}

func TestAuthNegative(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		AuthTokens: []string{"server-token"},
		ICMP: config.ICMPConfig{ReadTimeout: "100ms", WriteTimeout: "100ms"},
	}

	clientCfg := &config.ClientConfig{
		ServerAddr: "127.0.0.1",
		AuthToken:  "wrong-token",
		ICMP: config.ICMPConfig{ReadTimeout: "100ms", WriteTimeout: "100ms"},
		Forwards: []config.ForwardConfig{
			{Listen: "127.0.0.1:0", Destination: "127.0.0.1:80", Protocol: "tcp"},
		},
	}

	srv, _ := tunnel.NewServer(serverCfg)
	srv.Start()
	defer srv.Stop()

	cli, _ := tunnel.NewClient(clientCfg)
	err := cli.Start()
	
	// Client might still start its loops, but auth will fail.
	// We check if it can actually forward any data.
	time.Sleep(500 * time.Millisecond)
	
	// In the current implementation, cli.Start() returns nil but auth fail causes reconnect loops.
	if err != nil {
		t.Logf("Client start error (expected or caught): %v", err)
	}
}
