package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	proxyAddr      = flag.String("proxy", "127.0.0.1:1000", "SOCKS5 proxy address")
	targetHost     = flag.String("host", "speedtest.tele2.net", "Target host")
	targetPort     = flag.Int("port", 80, "Target port")
	streams        = flag.Int("streams", 100, "Number of parallel streams per client")
	mode           = flag.String("mode", "complete", "Mode: complete, abort, alternating")
	abortPct       = flag.Int("abort-pct", 50, "In alternating mode, percentage of streams to abort")
	timeout        = flag.Duration("timeout", 5*time.Minute, "Max duration per stream")
	abortDelay     = flag.Duration("abort-delay", 500*time.Millisecond, "How long to wait before aborting in abort mode")
	clientID       = flag.Int("id", 0, "Client ID for logging")
	jsonOutput     = flag.Bool("json", false, "Output results as JSON")
	dialTimeout    = flag.Duration("dial-timeout", 10*time.Second, "Dial timeout per stream")
	staggerDelay   = flag.Duration("stagger", 10*time.Millisecond, "Delay between launching streams")
	expectedSize   = flag.Int64("expected-size", 1048576, "Expected download size in bytes (1MB default)")
)

// StreamResult captures the outcome of a single stream
type StreamResult struct {
	StreamID      int           `json:"stream_id"`
	ShouldAbort   bool          `json:"should_abort"`
	Success       bool          `json:"success"`
	BytesReceived int64         `json:"bytes_received"`
	Duration      time.Duration `json:"duration_ms"`
	Error         string        `json:"error,omitempty"`
}

// ClientReport aggregates results for the entire client run
type ClientReport struct {
	ClientID         int            `json:"client_id"`
	TotalStreams      int            `json:"total_streams"`
	CompleteStreams   int            `json:"complete_streams"`
	AbortStreams      int            `json:"abort_streams"`
	SuccessComplete  int            `json:"success_complete"`
	SuccessAbort     int            `json:"success_abort"`
	FailedComplete   int            `json:"failed_complete"`
	FailedAbort      int            `json:"failed_abort"`
	TotalDuration    time.Duration  `json:"total_duration_ms"`
	MemAllocMB       float64        `json:"mem_alloc_mb"`
	MemSysMB         float64        `json:"mem_sys_mb"`
	Goroutines       int            `json:"goroutines"`
	StreamResults    []StreamResult `json:"stream_results,omitempty"`
}

func main() {
	flag.Parse()

	totalStreams := *streams
	abortCount := 0

	switch *mode {
	case "complete":
		abortCount = 0
	case "abort":
		abortCount = totalStreams
	case "alternating":
		abortCount = totalStreams * (*abortPct) / 100
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", *mode)
		os.Exit(2)
	}
	completeCount := totalStreams - abortCount

	// Build the schedule: which streams should abort
	shouldAbort := make([]bool, totalStreams)
	if *mode == "alternating" {
		// Interleave: every Nth stream aborts to create realistic mixed traffic
		if abortCount > 0 {
			step := totalStreams / abortCount
			if step < 1 {
				step = 1
			}
			assigned := 0
			for i := 0; i < totalStreams && assigned < abortCount; i++ {
				if i%step == step/2 { // offset to interleave nicely
					shouldAbort[i] = true
					assigned++
				}
			}
			// Fill remaining if needed
			for i := 0; i < totalStreams && assigned < abortCount; i++ {
				if !shouldAbort[i] {
					shouldAbort[i] = true
					assigned++
				}
			}
		}
	} else if *mode == "abort" {
		for i := range shouldAbort {
			shouldAbort[i] = true
		}
	}

	if !*jsonOutput {
		fmt.Printf("[Client %d] Starting: %d streams (%d complete, %d abort), mode=%s\n",
			*clientID, totalStreams, completeCount, abortCount, *mode)
	}

	var (
		wg              sync.WaitGroup
		successComplete int64
		successAbort    int64
		failComplete    int64
		failAbort       int64
		results         = make([]StreamResult, totalStreams)
	)

	startTime := time.Now()

	// Launch all streams with slight stagger to avoid thundering herd
	for i := 0; i < totalStreams; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			result := runStream(idx, shouldAbort[idx])
			results[idx] = result

			if shouldAbort[idx] {
				if result.Success {
					atomic.AddInt64(&successAbort, 1)
				} else {
					atomic.AddInt64(&failAbort, 1)
				}
			} else {
				if result.Success {
					atomic.AddInt64(&successComplete, 1)
				} else {
					atomic.AddInt64(&failComplete, 1)
				}
			}
		}()

		if *staggerDelay > 0 && i < totalStreams-1 {
			time.Sleep(*staggerDelay)
		}
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	// Memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	report := ClientReport{
		ClientID:        *clientID,
		TotalStreams:     totalStreams,
		CompleteStreams:  completeCount,
		AbortStreams:     abortCount,
		SuccessComplete: int(atomic.LoadInt64(&successComplete)),
		SuccessAbort:    int(atomic.LoadInt64(&successAbort)),
		FailedComplete:  int(atomic.LoadInt64(&failComplete)),
		FailedAbort:     int(atomic.LoadInt64(&failAbort)),
		TotalDuration:   totalDuration,
		MemAllocMB:      float64(memStats.Alloc) / 1024 / 1024,
		MemSysMB:        float64(memStats.Sys) / 1024 / 1024,
		Goroutines:      runtime.NumGoroutine(),
	}

	if *jsonOutput {
		report.StreamResults = results
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("[Client %d] Completed in %v\n", *clientID, totalDuration.Round(time.Millisecond))
		fmt.Printf("[Client %d]   Complete streams: %d/%d succeeded\n", *clientID, report.SuccessComplete, completeCount)
		fmt.Printf("[Client %d]   Abort streams:    %d/%d handled cleanly\n", *clientID, report.SuccessAbort, abortCount)
		fmt.Printf("[Client %d]   Memory: %.1f MB alloc, %.1f MB sys, %d goroutines\n",
			*clientID, report.MemAllocMB, report.MemSysMB, report.Goroutines)

		// Print failures in detail
		if report.FailedComplete > 0 {
			fmt.Printf("[Client %d]   ❌ %d complete streams FAILED:\n", *clientID, report.FailedComplete)
			shown := 0
			for _, r := range results {
				if !r.ShouldAbort && !r.Success {
					fmt.Printf("[Client %d]     Stream %d: %s (got %d bytes)\n", *clientID, r.StreamID, r.Error, r.BytesReceived)
					shown++
					if shown >= 10 {
						fmt.Printf("[Client %d]     ... and %d more\n", *clientID, report.FailedComplete-shown)
						break
					}
				}
			}
		}
	}

	// Exit code: fail if any "complete" stream failed
	if report.FailedComplete > 0 {
		os.Exit(1)
	}
}

func runStream(id int, shouldAbort bool) StreamResult {
	result := StreamResult{
		StreamID:    id,
		ShouldAbort: shouldAbort,
	}

	streamStart := time.Now()
	defer func() {
		result.Duration = time.Since(streamStart)
	}()

	conn, err := net.DialTimeout("tcp", *proxyAddr, *dialTimeout)
	if err != nil {
		if shouldAbort {
			result.Success = true // Connection failure is acceptable for abort streams
		} else {
			result.Error = fmt.Sprintf("dial proxy: %v", err)
		}
		return result
	}

	if shouldAbort {
		// For abort streams: set a short deadline to cause early termination
		conn.SetDeadline(time.Now().Add(*abortDelay))
	} else {
		conn.SetDeadline(time.Now().Add(*timeout))
	}

	// --- SOCKS5 Handshake ---
	// 1. Auth negotiation (No Auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("socks auth write: %v", err)
		return result
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("socks auth read: %v", err)
		return result
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		result.Error = fmt.Sprintf("bad socks handshake: %x", buf)
		return result
	}

	// 2. Connect Request (Domain Name)
	req := []byte{0x05, 0x01, 0x00, 0x03}
	hostBytes := []byte(*targetHost)
	if len(hostBytes) > 255 {
		conn.Close()
		result.Error = "host too long"
		return result
	}
	req = append(req, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(*targetPort))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("socks connect write: %v", err)
		return result
	}

	// 3. Connect Reply
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("socks connect read: %v", err)
		return result
	}
	if header[1] != 0x00 {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("socks connect failed code: %d", header[1])
		return result
	}

	// Skip rest of address
	switch header[3] {
	case 1: // IPv4
		io.CopyN(io.Discard, conn, 4+2)
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			if shouldAbort {
				result.Success = true
				return result
			}
			result.Error = fmt.Sprintf("socks addr read: %v", err)
			return result
		}
		io.CopyN(io.Discard, conn, int64(lenBuf[0])+2)
	case 4: // IPv6
		io.CopyN(io.Discard, conn, 16+2)
	}

	// 4. Send HTTP Request
	httpReq := "GET /1MB.zip HTTP/1.1\r\nHost: " + *targetHost + "\r\nUser-Agent: StressV2/1.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		conn.Close()
		if shouldAbort {
			result.Success = true
			return result
		}
		result.Error = fmt.Sprintf("http write: %v", err)
		return result
	}

	// 5. Read Response - count bytes
	n, err := io.Copy(io.Discard, conn)
	result.BytesReceived = n
	conn.Close()

	if shouldAbort {
		// For abort streams, any outcome is acceptable
		result.Success = true
		return result
	}

	// For complete streams, verify we got data
	if err != nil {
		result.Error = fmt.Sprintf("read error: %v (got %d bytes)", err, n)
		return result
	}

	// The HTTP response includes headers, so the total bytes > file size
	// We just check that we got at least the expected file size
	if n < *expectedSize {
		result.Error = fmt.Sprintf("incomplete download: got %d bytes, expected >= %d", n, *expectedSize)
		return result
	}

	result.Success = true
	return result
}
