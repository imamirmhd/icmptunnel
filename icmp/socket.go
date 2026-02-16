// Package icmp provides raw ICMP socket operations for the tunnel.
package icmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/imamirmhd/icmptunnel/logger"
)

// PacketPool provides reusable byte buffers for ICMP packets.
var PacketPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535+28) // Max IPv4 packet + safety
	},
}

// ReleaseBuffer returns a buffer to the pool.
func ReleaseBuffer(b []byte) {
	if cap(b) >= 65535 {
		PacketPool.Put(b)
	}
}

// sendBufPool for building outgoing packets without allocation.
var sendBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// Socket wraps a raw ICMP socket with send/receive capabilities.
type Socket struct {
	fd            int
	maxPacketSize int
	readTimeout   time.Duration
	writeTimeout  time.Duration
	log           *logger.Logger
	sendMu        sync.Mutex // Serialize sends to avoid interleaving
	localAddr     net.IP
	bound         bool
	workers       int
}

// NewSocket creates a new raw ICMP socket with IP_HDRINCL.
func NewSocket(maxPacketSize int, socketBufSizeMB int, readTimeout, writeTimeout time.Duration) (*Socket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket: %w (are you root?)", err)
	}

	// Enable IP_HDRINCL so we control the IP header
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}

	// Set large socket buffers for high throughput (default 32MB)
	bufSize := socketBufSizeMB * 1024 * 1024
	if bufSize < 16*1024*1024 {
		bufSize = 16 * 1024 * 1024
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)

	// Verify actual buffer sizes
	actualRcv, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	actualSnd, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)

	log := logger.Default().WithComponent("socket")
	log.Info("Socket buffers: rcv=%dMB snd=%dMB (requested %dMB)",
		actualRcv/1024/1024, actualSnd/1024/1024, socketBufSizeMB)

	return &Socket{
		fd:            fd,
		maxPacketSize: maxPacketSize,
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout,
		log:           log,
		workers:       4,
	}, nil
}

// Bind binds the socket to a local address.
func (s *Socket) Bind(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return fmt.Errorf("invalid bind address: %s", address)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported: %s", address)
	}

	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], ip4)

	if err := syscall.Bind(s.fd, addr); err != nil {
		return fmt.Errorf("binding to %s: %w", address, err)
	}

	s.localAddr = ip4
	s.bound = true
	s.log.Info("Socket bound to %s", address)
	return nil
}

// Close closes the socket.
func (s *Socket) Close() error {
	return syscall.Close(s.fd)
}

// FD returns the file descriptor.
func (s *Socket) FD() int {
	return s.fd
}

// SetReadDeadline sets the read timeout.
func (s *Socket) SetReadDeadline(d time.Duration) {
	s.readTimeout = d
	tv := syscall.Timeval{
		Sec:  int64(d / time.Second),
		Usec: int64((d % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// SetWriteDeadline sets the write timeout.
func (s *Socket) SetWriteDeadline(d time.Duration) {
	s.writeTimeout = d
}

// Receive reads an ICMP packet from the socket.
// Returns (srcIP, icmpType, icmpID, icmpSeq, payload, rawBuf, error).
// rawBuf should be returned to PacketPool via ReleaseBuffer when done.
func (s *Socket) Receive() (net.IP, uint8, uint16, uint16, []byte, []byte, error) {
	// Set read timeout
	if s.readTimeout > 0 {
		tv := syscall.Timeval{
			Sec:  int64(s.readTimeout / time.Second),
			Usec: int64((s.readTimeout % time.Second) / time.Microsecond),
		}
		syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	}

	buf := PacketPool.Get().([]byte)
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	if err != nil {
		PacketPool.Put(buf)
		if isTimeoutError(err) {
			return nil, 0, 0, 0, nil, nil, fmt.Errorf("read timeout")
		}
		return nil, 0, 0, 0, nil, nil, fmt.Errorf("recvfrom: %w", err)
	}

	if n < 28 { // Minimum: 20 IP + 8 ICMP
		PacketPool.Put(buf)
		return nil, 0, 0, 0, nil, nil, fmt.Errorf("packet too small: %d bytes", n)
	}

	// Parse IP header
	ipHeaderLen := int(buf[0]&0x0F) * 4
	if ipHeaderLen < 20 || ipHeaderLen >= n {
		PacketPool.Put(buf)
		return nil, 0, 0, 0, nil, nil, fmt.Errorf("invalid IP header length: %d", ipHeaderLen)
	}

	srcIP := net.IP(make([]byte, 4))
	copy(srcIP, buf[12:16])

	// Parse ICMP header
	icmpStart := ipHeaderLen
	if n-icmpStart < 8 {
		PacketPool.Put(buf)
		return nil, 0, 0, 0, nil, nil, fmt.Errorf("ICMP header too short")
	}

	icmpType := buf[icmpStart]
	icmpID := binary.BigEndian.Uint16(buf[icmpStart+4 : icmpStart+6])
	icmpSeq := binary.BigEndian.Uint16(buf[icmpStart+6 : icmpStart+8])

	// Payload is everything after the 8-byte ICMP header
	payloadStart := icmpStart + 8
	payload := buf[payloadStart:n]

	return srcIP, icmpType, icmpID, icmpSeq, payload, buf, nil
}

// Send sends an ICMP echo request with the given payload.
// Constructs both IP and ICMP headers (IP_HDRINCL mode).
func (s *Socket) Send(srcIP, dstIP net.IP, icmpID, icmpSeq uint16, payload []byte) error {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("invalid IPv4 addresses")
	}

	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen

	// Get buffer from pool
	buf := sendBufPool.Get().([]byte)
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	}
	buf = buf[:totalLen]
	defer sendBufPool.Put(buf)

	// IP Header (20 bytes)
	buf[0] = 0x45 // Version 4, IHL 5
	buf[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0) // ID
	binary.BigEndian.PutUint16(buf[6:8], 0) // Flags + Fragment Offset
	buf[8] = 64                              // TTL
	buf[9] = 1                               // Protocol: ICMP
	buf[10] = 0                              // Header checksum (kernel fills)
	buf[11] = 0
	copy(buf[12:16], src4)
	copy(buf[16:20], dst4)

	// ICMP Header (8 bytes)
	buf[20] = 8 // Type: Echo Request
	buf[21] = 0 // Code
	buf[22] = 0 // Checksum (fill after)
	buf[23] = 0
	binary.BigEndian.PutUint16(buf[24:26], icmpID)
	binary.BigEndian.PutUint16(buf[26:28], icmpSeq)

	// Payload
	copy(buf[28:], payload)

	// Calculate ICMP checksum
	cksum := Checksum(buf[20:totalLen])
	binary.BigEndian.PutUint16(buf[22:24], cksum)

	// Send
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dst4)

	s.sendMu.Lock()
	err := syscall.Sendto(s.fd, buf[:totalLen], 0, addr)
	s.sendMu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto %s: %w", dstIP, err)
	}
	return nil
}

// SendReply sends an ICMP echo reply with the given payload.
func (s *Socket) SendReply(srcIP, dstIP net.IP, icmpID, icmpSeq uint16, payload []byte) error {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("invalid IPv4 addresses")
	}

	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen

	buf := sendBufPool.Get().([]byte)
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	}
	buf = buf[:totalLen]
	defer sendBufPool.Put(buf)

	// IP Header
	buf[0] = 0x45
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	buf[8] = 64
	buf[9] = 1
	buf[10] = 0
	buf[11] = 0
	copy(buf[12:16], src4)
	copy(buf[16:20], dst4)

	// ICMP Header - Echo Reply
	buf[20] = 0 // Type: Echo Reply
	buf[21] = 0
	buf[22] = 0
	buf[23] = 0
	binary.BigEndian.PutUint16(buf[24:26], icmpID)
	binary.BigEndian.PutUint16(buf[26:28], icmpSeq)

	copy(buf[28:], payload)

	cksum := Checksum(buf[20:totalLen])
	binary.BigEndian.PutUint16(buf[22:24], cksum)

	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dst4)

	s.sendMu.Lock()
	err := syscall.Sendto(s.fd, buf[:totalLen], 0, addr)
	s.sendMu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto reply %s: %w", dstIP, err)
	}
	return nil
}

// Checksum computes the Internet checksum (RFC 1071).
func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	i := 0

	// Process 4 bytes at a time for speed
	for i+3 < length {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		sum += uint32(data[i+2])<<8 | uint32(data[i+3])
		i += 4
	}
	for i+1 < length {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		i += 2
	}
	if i < length {
		sum += uint32(data[i]) << 8
	}

	// Fold 32-bit sum into 16 bits
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func isTimeoutError(err error) bool {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return true
	}
	return strings.Contains(err.Error(), "timeout")
}
