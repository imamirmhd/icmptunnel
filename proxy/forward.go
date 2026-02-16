package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/imamirmhd/icmptunnel/logger"
)

// Forwarder listens on a local port and forwards traffic through the tunnel.
type Forwarder struct {
	listener    net.Listener
	listenAddr  string
	destination string
	protocol    string
	log         *logger.Logger
}

// NewForwarder creates a new port forwarder.
func NewForwarder(listen, destination, protocol string) (*Forwarder, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", listen, err)
	}

	return &Forwarder{
		listener:    ln,
		listenAddr:  listen,
		destination: destination,
		protocol:    protocol,
		log:         logger.Default().WithComponent("forward"),
	}, nil
}

// Serve starts accepting connections and forwarding them.
func (f *Forwarder) Serve(connect ConnectFunc) {
	f.log.Info("Forwarding %s -> %s (%s)", f.listenAddr, f.destination, f.protocol)

	for {
		conn, err := f.listener.Accept()
		if err != nil {
			f.log.Error("Accept: %v", err)
			return
		}
		go f.handleConnection(conn, connect)
	}
}

func (f *Forwarder) handleConnection(conn net.Conn, connect ConnectFunc) {
	defer func() {
		if r := recover(); r != nil {
			f.log.Error("[PANIC] Forward handler: %v", r)
		}
		conn.Close()
	}()

	sendCh, recvCh, err := connect(f.destination)
	if err != nil {
		f.log.Error("Tunnel connect failed: %v", err)
		return
	}

	var wg sync.WaitGroup

	// Local -> tunnel
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				f.log.Error("[PANIC] Forward uplink: %v", r)
			}
		}()
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					f.log.Debug("Forward read: %v", err)
				}
				close(sendCh)
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			sendCh <- data
		}
	}()

	// Tunnel -> local
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				f.log.Error("[PANIC] Forward downlink: %v", r)
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

// Close stops the forwarder.
func (f *Forwarder) Close() error {
	return f.listener.Close()
}
