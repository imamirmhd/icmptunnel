// Package proxy provides SOCKS5 proxy and TCP/UDP port forwarding for the client side.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/user/icmptunnel/logger"
)

// DataHandler is called when proxy data needs to be sent through the tunnel.
type DataHandler func(streamID uint16, data []byte) error

// ConnectHandler is called when a new connection needs to be established through the tunnel.
// Returns a streamID for this connection.
type ConnectHandler func(protocol, destination string) (uint16, chan []byte, error)

// CloseHandler is called when a stream should be closed.
type CloseHandler func(streamID uint16)

// Socks5Server implements a SOCKS5 proxy server (RFC 1928).
type Socks5Server struct {
	listenAddr string
	username   string
	password   string
	listener   net.Listener
	onConnect  ConnectHandler
	onData     DataHandler
	onClose    CloseHandler
	log        *logger.Logger
	wg         sync.WaitGroup
	done       chan struct{}
}

// NewSocks5Server creates a new SOCKS5 proxy server.
func NewSocks5Server(listenAddr, username, password string,
	onConnect ConnectHandler, onData DataHandler, onClose CloseHandler) *Socks5Server {
	return &Socks5Server{
		listenAddr: listenAddr,
		username:   username,
		password:   password,
		onConnect:  onConnect,
		onData:     onData,
		onClose:    onClose,
		log:        logger.Default().WithComponent("socks5"),
		done:       make(chan struct{}),
	}
}

// Start begins listening for SOCKS5 connections.
func (s *Socks5Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.listenAddr, err)
	}

	s.log.Info("SOCKS5 server listening on %s", s.listenAddr)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.done:
					return
				default:
					s.log.Error("Accept error: %v", err)
					continue
				}
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(conn)
			}()
		}
	}()

	return nil
}

// Stop shuts down the SOCKS5 server.
func (s *Socks5Server) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Socks5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Step 1: Method negotiation
	if err := s.negotiateAuth(conn); err != nil {
		s.log.Error("Auth negotiation failed: %v", err)
		return
	}

	// Step 2: Read connect request
	dest, err := s.readRequest(conn)
	if err != nil {
		s.log.Error("Request failed: %v", err)
		return
	}

	s.log.Info("CONNECT %s", dest)

	// Step 3: Establish tunnel stream
	streamID, responseChan, err := s.onConnect("tcp", dest)
	if err != nil {
		s.log.Error("Connect to %s failed: %v", dest, err)
		s.sendReply(conn, 0x05) // Connection refused
		return
	}
	defer s.onClose(streamID)

	// Step 4: Send success reply
	s.sendReply(conn, 0x00) // Succeeded

	// Step 5: Bidirectional data relay
	doneCh := make(chan struct{}, 2)

	// Client -> Tunnel
	go func() {
		defer func() { doneCh <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := s.onData(streamID, buf[:n]); err != nil {
				return
			}
		}
	}()

	// Tunnel -> Client
	go func() {
		defer func() { doneCh <- struct{}{} }()
		for {
			select {
			case data, ok := <-responseChan:
				if !ok {
					return
				}
				if _, err := conn.Write(data); err != nil {
					return
				}
			case <-s.done:
				return
			}
		}
	}()

	<-doneCh
}

func (s *Socks5Server) negotiateAuth(conn net.Conn) error {
	// Read version + number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading auth header: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	// Read methods
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading auth methods: %w", err)
	}

	if s.username != "" {
		// Require username/password auth (method 0x02)
		conn.Write([]byte{0x05, 0x02})
		return s.authenticateUserPass(conn)
	}

	// No auth required (method 0x00)
	conn.Write([]byte{0x05, 0x00})
	return nil
}

func (s *Socks5Server) authenticateUserPass(conn net.Conn) error {
	// RFC 1929 - Username/Password auth
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	// Read username
	ulen := int(header[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	// Read password length + password
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if string(uname) != s.username || string(passwd) != s.password {
		conn.Write([]byte{0x01, 0x01}) // Failure
		return fmt.Errorf("authentication failed")
	}

	conn.Write([]byte{0x01, 0x00}) // Success
	return nil
}

func (s *Socks5Server) readRequest(conn net.Conn) (string, error) {
	// Read: VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	if header[1] != 0x01 { // Only CONNECT supported
		s.sendReply(conn, 0x07) // Command not supported
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	// Read destination address
	var host string
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	default:
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *Socks5Server) sendReply(conn net.Conn, status byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}
