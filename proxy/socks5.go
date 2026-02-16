// Package proxy provides SOCKS5 and port forwarding proxy servers.
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/imamirmhd/icmptunnel/logger"
)

// ConnectFunc is called when a SOCKS5 client requests a connection.
// Returns (sendCh, recvCh, error).
type ConnectFunc func(destination string) (chan<- []byte, <-chan []byte, error)

// SOCKS5Server implements a SOCKS5 proxy server.
type SOCKS5Server struct {
	listener net.Listener
	log      *logger.Logger
	username string
	password string
}

// NewSOCKS5Server creates a new SOCKS5 server.
func NewSOCKS5Server(listen, username, password string) (*SOCKS5Server, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", listen, err)
	}

	return &SOCKS5Server{
		listener: ln,
		log:      logger.Default().WithComponent("socks5"),
		username: username,
		password: password,
	}, nil
}

// Serve starts accepting SOCKS5 connections.
func (s *SOCKS5Server) Serve(connect ConnectFunc) {
	s.log.Info("SOCKS5 server listening on %s", s.listener.Addr())

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.log.Error("Accept: %v", err)
			return
		}

		go s.handleConnection(conn, connect)
	}
}

// Close stops the SOCKS5 server.
func (s *SOCKS5Server) Close() error {
	return s.listener.Close()
}

func (s *SOCKS5Server) handleConnection(conn net.Conn, connect ConnectFunc) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("[PANIC] SOCKS5 handler: %v", r)
		}
		conn.Close()
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	version := buf[0]
	if version != 0x05 {
		return
	}

	// Auth negotiation
	nMethods := int(buf[1])
	if n < 2+nMethods {
		return
	}

	methods := buf[2 : 2+nMethods]

	if s.username != "" {
		// Require username/password auth
		hasAuthMethod := false
		for _, m := range methods {
			if m == 0x02 {
				hasAuthMethod = true
				break
			}
		}
		if !hasAuthMethod {
			conn.Write([]byte{0x05, 0xFF})
			return
		}

		conn.Write([]byte{0x05, 0x02})

		// Read auth
		n, err = conn.Read(buf)
		if err != nil || n < 3 {
			return
		}

		uLen := int(buf[1])
		if n < 2+uLen+1 {
			return
		}
		username := string(buf[2 : 2+uLen])
		pLen := int(buf[2+uLen])
		if n < 3+uLen+pLen {
			return
		}
		password := string(buf[3+uLen : 3+uLen+pLen])

		if username != s.username || password != s.password {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		s.sendReply(conn, 0x07)
		return
	}

	// Parse address
	var host string
	var port uint16

	addrType := buf[3]
	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])

	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])

	case 0x04: // IPv6
		if n < 22 {
			return
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])

	default:
		s.sendReply(conn, 0x08)
		return
	}

	destination := fmt.Sprintf("%s:%d", host, port)
	s.log.Debug("SOCKS5 connect: %s", destination)

	conn.SetDeadline(time.Time{}) // Remove deadline for data transfer

	sendCh, recvCh, err := connect(destination)
	if err != nil {
		s.log.Error("Tunnel connect failed: %v", err)
		s.sendReply(conn, 0x04)
		return
	}

	// Send success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], port)
	conn.Write(reply)

	// Bidirectional relay with crash guards
	var wg sync.WaitGroup

	// Client -> tunnel
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("[PANIC] SOCKS5 uplink: %v", r)
			}
		}()

		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(sendCh)
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case sendCh <- data:
			default:
				// Backpressure: block
				sendCh <- data
			}
		}
	}()

	// Tunnel -> client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("[PANIC] SOCKS5 downlink: %v", r)
			}
		}()

		for data := range recvCh {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (s *SOCKS5Server) sendReply(conn net.Conn, status byte) {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}
