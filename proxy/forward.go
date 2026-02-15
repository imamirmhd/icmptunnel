package proxy

import (
	"fmt"
	"net"
	"sync"

	"github.com/user/icmptunnel/logger"
)

// Forwarder handles TCP and UDP port forwarding rules.
type Forwarder struct {
	listen      string
	destination string
	protocol    string
	onConnect   ConnectHandler
	onData      DataHandler
	onClose     CloseHandler
	maxDataSize int
	listener    net.Listener
	udpConn     *net.UDPConn
	log         *logger.Logger
	wg          sync.WaitGroup
	done        chan struct{}
	conns       map[net.Conn]struct{}
	connsMu     sync.Mutex
}

// NewForwarder creates a new port forwarder.
func NewForwarder(listen, destination, protocol string, maxDataSize int,
	onConnect ConnectHandler, onData DataHandler, onClose CloseHandler) *Forwarder {
	return &Forwarder{
		listen:      listen,
		destination: destination,
		protocol:    protocol,
		onConnect:   onConnect,
		onData:      onData,
		onClose:     onClose,
		maxDataSize: maxDataSize,
		log:         logger.Default().WithComponent("forward"),
		done:        make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
	}
}

// Start begins listening and forwarding connections.
func (f *Forwarder) Start() error {
	switch f.protocol {
	case "tcp":
		return f.startTCP()
	case "udp":
		return f.startUDP()
	default:
		return fmt.Errorf("unsupported protocol: %s", f.protocol)
	}
}

// Stop shuts down the forwarder.
func (f *Forwarder) Stop() {
	close(f.done)
	if f.listener != nil {
		f.listener.Close()
	}
	
	f.connsMu.Lock()
	for conn := range f.conns {
		conn.Close()
	}
	f.connsMu.Unlock()

	if f.udpConn != nil {
		f.udpConn.Close()
	}
	f.wg.Wait()
}

func (f *Forwarder) startTCP() error {
	var err error
	f.listener, err = net.Listen("tcp", f.listen)
	if err != nil {
		return fmt.Errorf("listening TCP on %s: %w", f.listen, err)
	}

	f.log.Info("TCP forwarder %s -> %s", f.listen, f.destination)

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				select {
				case <-f.done:
					return
				default:
					f.log.Error("TCP accept: %v", err)
					continue
				}
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.handleTCPConn(conn)
			}()
		}
	}()

	return nil
}

func (f *Forwarder) handleTCPConn(conn net.Conn) {
	f.connsMu.Lock()
	f.conns[conn] = struct{}{}
	f.connsMu.Unlock()

	defer func() {
		conn.Close()
		f.connsMu.Lock()
		delete(f.conns, conn)
		f.connsMu.Unlock()
	}()

	streamID, responseChan, err := f.onConnect("tcp", f.destination)
	if err != nil {
		select {
		case <-f.done:
			return
		default:
			f.log.Error("Connect failed: %v", err)
		}
		return
	}
	defer f.onClose(streamID)

	// Step 5: Bidirectional data relay
	var relayWg sync.WaitGroup
	relayWg.Add(2)

	var closeOnce sync.Once
	closeNotifier := make(chan struct{})
	closeConn := func() {
		closeOnce.Do(func() {
			close(closeNotifier)
			conn.Close()
		})
	}

	// Local -> Tunnel
	go func() {
		defer relayWg.Done()
		defer closeConn() // Close connection if read fails
		defer f.onClose(streamID) // Ensure tunnel stream is closed
		
		bufSize := f.maxDataSize
		if bufSize <= 0 {
			bufSize = 32 * 1024
		}
		buf := make([]byte, bufSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := f.onData(streamID, buf[:n]); err != nil {
				return
			}
		}
	}()

	// Tunnel -> Local
	go func() {
		defer relayWg.Done()
		defer closeConn()
		
		for {
			select {
			case data, ok := <-responseChan:
				if !ok {
					return
				}
				if _, err := conn.Write(data); err != nil {
					return
				}
			case <-closeNotifier:
				return
			case <-f.done:
				return
			}
		}
	}()

	relayWg.Wait()
}

func (f *Forwarder) startUDP() error {
	udpAddr, err := net.ResolveUDPAddr("udp", f.listen)
	if err != nil {
		return fmt.Errorf("resolving UDP address %s: %w", f.listen, err)
	}

	f.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening UDP on %s: %w", f.listen, err)
	}

	f.log.Info("UDP forwarder %s -> %s", f.listen, f.destination)

	// Track client addresses for response routing
	type udpClient struct {
		addr      *net.UDPAddr
		streamID  uint16
		respChan  chan []byte
	}
	clients := make(map[string]*udpClient)
	var mu sync.Mutex

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		bufSize := f.maxDataSize
		if bufSize <= 0 {
			bufSize = 65535
		}
		buf := make([]byte, bufSize)
		for {
			select {
			case <-f.done:
				return
			default:
			}

			n, clientAddr, err := f.udpConn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-f.done:
					return
				default:
					f.log.Error("UDP read: %v", err)
					continue
				}
			}

			key := clientAddr.String()
			mu.Lock()
			client, exists := clients[key]
			if !exists {
				streamID, respChan, err := f.onConnect("udp", f.destination)
				if err != nil {
					mu.Unlock()
					f.log.Error("UDP connect failed: %v", err)
					continue
				}
				client = &udpClient{
					addr:     clientAddr,
					streamID: streamID,
					respChan: respChan,
				}
				clients[key] = client

				// Start response handler
				go func(c *udpClient) {
					for {
						select {
						case data, ok := <-c.respChan:
							if !ok {
								return
							}
							f.udpConn.WriteToUDP(data, c.addr)
						case <-f.done:
							return
						}
					}
				}(client)
			}
			mu.Unlock()

			data := make([]byte, n)
			copy(data, buf[:n])
			f.onData(client.streamID, data)
		}
	}()

	return nil
}
