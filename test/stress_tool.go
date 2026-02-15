package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	proxyAddr   = flag.String("proxy", "127.0.0.1:1000", "SOCKS5 proxy address")
	targetHost  = flag.String("host", "speedtest.tele2.net", "Target host")
	targetPort  = flag.Int("port", 80, "Target port")
	concurrency = flag.Int("c", 100, "Number of concurrent streams")
	abort       = flag.Bool("abort", false, "Abort connection early")
	timeout     = flag.Duration("timeout", 5*time.Minute, "Max duration per stream")
)

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	var successCount int64
	var failCount int64

	start := time.Now()
	// fmt.Printf("Starting stress tool: %d streams, abort=%v, target=%s:%d\n", *concurrency, *abort, *targetHost, *targetPort)

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if err := runStream(id); err != nil {
				if !*abort {
					// fmt.Printf("Stream %d failed: %v\n", id, err)
					atomic.AddInt64(&failCount, 1)
				}
			} else {
				if !*abort {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	if !*abort {
		fmt.Printf("Completed in %v. Success: %d, Fail: %d\n", duration, successCount, failCount)
		if failCount > 0 {
			os.Exit(1)
		}
	} else {
		// In abort mode, we expect failures/timeouts, so just verify process completed
		fmt.Printf("Aborted load completed in %v\n", duration)
	}
}

func runStream(id int) error {
	conn, err := net.DialTimeout("tcp", *proxyAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial proxy: %w", err)
	}
	defer conn.Close()

	if *abort {
		// Set a short deadline to force close during handshake or early transfer
		conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	} else {
		conn.SetDeadline(time.Now().Add(*timeout))
	}

	// SOCKS5 Handshake
	// 1. Auth negotiation (No Auth)
	// VER=5, NMETHODS=1, METHOD=0 (No Auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("bad socks handshake: %x", buf)
	}

	// 2. Connect Request (Using Domain Name 0x03)
	// VER=5, CMD=1(Connect), RSV=0, ATYP=3(Domain)
	// + Len + Domain + Port (2 bytes)
	req := []byte{0x05, 0x01, 0x00, 0x03}
	hostBytes := []byte(*targetHost)
	if len(hostBytes) > 255 {
		return fmt.Errorf("host too long")
	}
	req = append(req, byte(len(hostBytes)))
	req = append(req, hostBytes...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(*targetPort))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// 3. Connect Reply
	// VER=5, REP, RSV, ATYP, BND.ADDR, BND.PORT
	// We read at least 4 bytes to check REP code
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks connect failed code: %d", header[1])
	}

	// Skip rest of address (variable length)
	switch header[3] {
	case 1: // IPv4
		io.CopyN(io.Discard, conn, 4+2)
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		io.CopyN(io.Discard, conn, int64(lenBuf[0])+2)
	case 4: // IPv6
		io.CopyN(io.Discard, conn, 16+2)
	}

	// 4. Send HTTP Request
	// Use local buffer for the request, but discard response
	reqStr := "GET /1MB.zip HTTP/1.1\r\nHost: " + *targetHost + "\r\nUser-Agent: StressTest/1.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return err
	}

	// 5. Read Response
	// In abort mode, the deadline will likely fire here
	_, err = io.Copy(io.Discard, conn)

	// Check if error is timeout in abort mode
	if *abort {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil // Success for abort test
		}
		return nil // Any error is fine for abort test
	}

	return err
}
