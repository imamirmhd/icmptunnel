// Package icmp provides raw ICMP socket operations for the tunnel.
package icmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/user/icmptunnel/logger"
)

// Socket wraps a raw ICMP socket with send/receive capabilities.
type Socket struct {
	fd            int
	maxPacketSize int
	ttl           int
	readTimeout   time.Duration
	writeTimeout  time.Duration
	log           *logger.Logger
}

// NewSocket creates and configures a raw ICMP socket.
func NewSocket(maxPacketSize, ttl int, readTimeout, writeTimeout time.Duration) (*Socket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket: %w (are you root?)", err)
	}

	// Set IP_HDRINCL so we can construct our own IP headers (needed for spoofing).
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}

	// Set receive buffer size.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024); err != nil {
		// Non-fatal, just log.
	}

	// Set send buffer size.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024*1024); err != nil {
		// Non-fatal.
	}

	return &Socket{
		fd:            fd,
		maxPacketSize: maxPacketSize,
		ttl:           ttl,
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout,
		log:           logger.Default().WithComponent("icmp-socket"),
	}, nil
}

// Bind binds the socket to INADDR_ANY for receiving all ICMP traffic.
func (s *Socket) Bind() error {
	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], net.IPv4zero.To4())
	if err := syscall.Bind(s.fd, &addr); err != nil {
		return fmt.Errorf("binding socket: %w", err)
	}
	return nil
}

// Send sends an ICMP packet to the destination with the given source address.
func (s *Socket) Send(srcIP, destIP net.IP, icmpType uint8, id, seq uint16, payload []byte) error {
	src4 := srcIP.To4()
	dst4 := destIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported")
	}

	packetSize := 20 + 8 + len(payload) // IP header + ICMP header + payload
	if packetSize > s.maxPacketSize+20 {
		return fmt.Errorf("packet size %d exceeds max %d", packetSize, s.maxPacketSize+20)
	}

	packet := make([]byte, packetSize)

	// IP Header (20 bytes)
	packet[0] = 0x45                                           // Version 4, IHL 5
	packet[1] = 0                                              // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(packetSize)) // Total length
	binary.BigEndian.PutUint16(packet[4:6], uint16(randID()))  // ID
	binary.BigEndian.PutUint16(packet[6:8], 0)                 // Flags + Fragment offset
	packet[8] = byte(s.ttl)                                    // TTL
	packet[9] = syscall.IPPROTO_ICMP                           // Protocol
	binary.BigEndian.PutUint16(packet[10:12], 0)               // Checksum (kernel fills)
	copy(packet[12:16], src4)                                  // Source IP
	copy(packet[16:20], dst4)                                  // Dest IP

	// ICMP Header (8 bytes)
	packet[20] = icmpType  // Type
	packet[21] = 0         // Code
	packet[22] = 0         // Checksum (fill later)
	packet[23] = 0
	binary.BigEndian.PutUint16(packet[24:26], id)  // ID
	binary.BigEndian.PutUint16(packet[26:28], seq) // Sequence

	// Payload
	copy(packet[28:], payload)

	// Calculate ICMP checksum
	cksum := Checksum(packet[20:])
	binary.BigEndian.PutUint16(packet[22:24], cksum)

	// Set write deadline
	tv := syscall.NsecToTimeval(s.writeTimeout.Nanoseconds())
	syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	// Send
	dest := syscall.SockaddrInet4{Port: 0}
	copy(dest.Addr[:], dst4)
	return syscall.Sendto(s.fd, packet, 0, &dest)
}

// SendEcho sends an ICMP echo request with specific or random ID/Seq.
// If id/seq are 0, they will be generated randomly.
func (s *Socket) SendEcho(srcIP, destIP net.IP, id, seq uint16, payload []byte) error {
	if id == 0 {
		id = randID()
	}
	if seq == 0 {
		seq = randID()
	}
	return s.Send(srcIP, destIP, 8, id, seq, payload) // ICMP Echo Request = 8
}

// SendReply sends an ICMP echo reply matching the given ID and Sequence.
func (s *Socket) SendReply(srcIP, destIP net.IP, id, seq uint16, payload []byte) error {
	return s.Send(srcIP, destIP, 0, id, seq, payload) // ICMP Echo Reply = 0
}

// Receive reads one ICMP packet from the socket.
// Returns the source IP, ICMP type, ID, Sequence, and payload.
func (s *Socket) Receive() (srcIP net.IP, icmpType uint8, id, seq uint16, payload []byte, err error) {
	buf := make([]byte, s.maxPacketSize+20+8)

	// Set read deadline
	tv := syscall.NsecToTimeval(s.readTimeout.Nanoseconds())
	syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	n, from, err := syscall.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return nil, 0, 0, 0, nil, fmt.Errorf("receiving: %w", err)
	}

	if n < 28 { // Min: 20 IP + 8 ICMP
		return nil, 0, 0, 0, nil, fmt.Errorf("packet too small: %d bytes", n)
	}

	// Extract source IP from sockaddr
	if sa, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	} else {
		return nil, 0, 0, 0, nil, fmt.Errorf("unexpected sockaddr type")
	}

	// Parse IP header to get IHL
	ihl := int(buf[0]&0x0f) * 4
	if n < ihl+8 {
		return nil, 0, 0, 0, nil, fmt.Errorf("packet too small for headers")
	}

	// ICMP type
	icmpType = buf[ihl]
	
	// Extract ID and Sequence (bytes 4-8 of ICMP header, which starts at ihl)
	id = binary.BigEndian.Uint16(buf[ihl+4 : ihl+6])
	seq = binary.BigEndian.Uint16(buf[ihl+6 : ihl+8])

	// Payload starts after IP header + 8 byte ICMP header
	payloadStart := ihl + 8
	if n > payloadStart {
		payload = make([]byte, n-payloadStart)
		copy(payload, buf[payloadStart:n])
	}

	return srcIP, icmpType, id, seq, payload, nil
}

// Close closes the raw socket.
func (s *Socket) Close() error {
	return syscall.Close(s.fd)
}

// Checksum computes the Internet checksum (RFC 1071) for an ICMP packet.
func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i+1 < length; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return ^uint16(sum)
}

// randID generates a random 16-bit ID.
func randID() uint16 {
	// Use a simple counter-based approach for better performance.
	return uint16(time.Now().UnixNano() & 0xFFFF)
}
