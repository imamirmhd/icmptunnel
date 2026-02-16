package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/tunnel"
)

// setupEchoServer starts a TCP echo server on a random port.
// It returns the listener address and a cleanup function.
func setupEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setupEchoServer: net.Listen failed: %v", err)
	}

	_, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Use context to close connections early on server stop if needed
				io.Copy(c, c)
			}(conn)
		}
	}()

	return l.Addr().String(), func() {
		cancel()
		l.Close()
	}
}

// TunnelOptions defines parameters for setting up a test tunnel.
type TunnelOptions struct {
	EncryptionMethod string
	EncryptionKey    string
	EncryptionEnabled bool
	AuthToken        string
	Compression      bool
	Forwards         []config.ForwardConfig
	Socks5           []config.Socks5Config
	Transport        config.TransportConfig
}

// setupTunnel creates and starts a tunnel server and client.
// It returns the server, client, and a cleanup function.
func setupTunnel(t *testing.T, opts TunnelOptions) (*tunnel.Server, *tunnel.Client, func()) {
	t.Helper()

	// 1. Server Config
	serverCfg := &config.ServerConfig{
		Listen: "127.0.0.1",
		ICMP: config.ICMPConfig{
			ReadTimeout:   "500ms",
			WriteTimeout:  "500ms",
			MaxPacketSize: 1472,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{
			Enabled: opts.EncryptionEnabled,
			Method:  opts.EncryptionMethod,
			Key:     opts.EncryptionKey,
		},
		AuthTokens: []string{opts.AuthToken},
		Logging:    config.LoggingConfig{Level: "info", Output: "stdout"},
		Transport:  opts.Transport,
	}

	if serverCfg.Transport.WindowSize == 0 {
		serverCfg.Transport.WindowSize = 100
	}
	serverCfg.Transport.Compression = opts.Compression

	// 2. Client Config
	clientCfg := &config.ClientConfig{
		ServerAddr: "127.0.0.1",
		BindAddr:   "127.0.0.1",
		AuthToken:  opts.AuthToken,
		ICMP: config.ICMPConfig{
			ReadTimeout:   "500ms",
			WriteTimeout:  "500ms",
			MaxPacketSize: 1472,
			TTL:           64,
		},
		Encryption: config.EncryptionConfig{
			Enabled: opts.EncryptionEnabled,
			Method:  opts.EncryptionMethod,
			Key:     opts.EncryptionKey,
		},
		Logging:  config.LoggingConfig{Level: "info", Output: "stdout"},
		Forwards: opts.Forwards,
		Socks5:   opts.Socks5,
		Transport: opts.Transport,
	}

	if clientCfg.Transport.WindowSize == 0 {
		clientCfg.Transport.WindowSize = 100
	}
	clientCfg.Transport.Compression = opts.Compression

	// 3. Start Server
	srv, err := tunnel.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}

	// 4. Start Client
	cli, err := tunnel.NewClient(clientCfg)
	if err != nil {
		srv.Stop()
		t.Fatalf("NewClient: %v", err)
	}
	if err := cli.Start(); err != nil {
		cli.Stop()
		srv.Stop()
		t.Fatalf("cli.Start: %v", err)
	}

	// Wait for auth
	time.Sleep(1 * time.Second)

	return srv, cli, func() {
		cli.Stop()
		srv.Stop()
	}
}

// verifyEcho sends data through conn and verifies that it is echoed back correctly.
func verifyEcho(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}

	resp := make([]byte, size)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}

	if !bytes.Equal(payload, resp) {
		t.Errorf("echo mismatch: sent %d bytes, read %d bytes", len(payload), len(resp))
	}
}

// dialSocks5 establishes a SOCKS5 connection to proxyAddr and returns a connection to targetAddr.
// Note: This is a minimal manual implementation to avoid external dependencies.
func dialSocks5(t *testing.T, proxyAddr, targetAddr string, user, pass string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dialSocks5: net.Dial %s failed: %v", proxyAddr, err)
	}

	// 1. Handshake
	authMethod := byte(0x00) // No auth
	if user != "" {
		authMethod = 0x02 // Username/Password
	}
	if _, err := conn.Write([]byte{0x05, 0x01, authMethod}); err != nil {
		conn.Close()
		t.Fatalf("socks5 handshake write: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("socks5 handshake read: %v", err)
	}
	if resp[0] != 0x05 {
		conn.Close()
		t.Fatalf("socks5 version mismatch: %d", resp[0])
	}
	if resp[1] != authMethod {
		conn.Close()
		t.Fatalf("socks5 auth method refused: %d", resp[1])
	}

	// 2. Auth if needed
	if user != "" {
		buf := bytes.NewBuffer([]byte{0x01}) // Subnegotiation version
		buf.WriteByte(byte(len(user)))
		buf.WriteString(user)
		buf.WriteByte(byte(len(pass)))
		buf.WriteString(pass)
		if _, err := conn.Write(buf.Bytes()); err != nil {
			conn.Close()
			t.Fatalf("socks5 auth write: %v", err)
		}
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			t.Fatalf("socks5 auth read: %v", err)
		}
		if resp[1] != 0x00 {
			conn.Close()
			t.Fatalf("socks5 auth failed: %d", resp[1])
		}
	}

	// 3. Connect Request
	host, portStr, _ := net.SplitHostPort(targetAddr)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	req := bytes.NewBuffer([]byte{0x05, 0x01, 0x00, 0x03}) // ATYP Domain
	req.WriteByte(byte(len(host)))
	req.WriteString(host)
	req.WriteByte(byte(port >> 8))
	req.WriteByte(byte(port & 0xFF))

	if _, err := conn.Write(req.Bytes()); err != nil {
		conn.Close()
		t.Fatalf("socks5 connect write: %v", err)
	}

	// 4. Connect Response
	// VER REP RSV ATYP BND.ADDR BND.PORT
	// Domain addr response can be variable size, but we just need enough to verify success.
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		conn.Close()
		t.Fatalf("socks5 connect resp read: %v", err)
	}
	if respHeader[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks5 connect failed with status: %d", respHeader[1])
	}
	// Read address and port and discard
	var toRead int
	switch respHeader[3] {
	case 0x01: toRead = 4+2 // IPv4
	case 0x03:
		l := make([]byte, 1)
		conn.Read(l)
		toRead = int(l[0]) + 2 // Domain
	case 0x04: toRead = 16+2 // IPv6
	}
	if toRead > 0 {
		io.ReadFull(conn, make([]byte, toRead))
	}

	return conn
}

// getResourceStats returns current memory stats and goroutine count.
func getResourceStats() (uint64, int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc, runtime.NumGoroutine()
}
