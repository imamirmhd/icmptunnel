// Package diag provides diagnostic and debugging tools for ICMP tunnels.
package diag

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/imamirmhd/icmptunnel/icmp"
	"github.com/imamirmhd/icmptunnel/logger"
)

// Diagnostics provides tools for testing tunnel connectivity.
type Diagnostics struct {
	socket    *icmp.Socket
	log       *logger.Logger
	authToken string
}

// New creates a new Diagnostics instance.
func New() (*Diagnostics, error) {
	sock, err := icmp.NewSocket(1472, 16, 5*time.Second, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if err := sock.Bind("0.0.0.0"); err != nil {
		sock.Close()
		return nil, err
	}

	return &Diagnostics{
		socket: sock,
		log:    logger.Default().WithComponent("diag"),
	}, nil
}

// Close closes the diagnostics socket.
func (d *Diagnostics) Close() {
	d.socket.Close()
}

// SetAuthToken sets the auth token for diagnostic packets.
func (d *Diagnostics) SetAuthToken(token string) {
	d.authToken = token
}

// PingResult holds results from a ping test.
type PingResult struct {
	Target    string
	Sent      int
	Received  int
	LossRate  float64
	MinRTT    time.Duration
	MaxRTT    time.Duration
	AvgRTT    time.Duration
	RTTs      []time.Duration
}

// Ping performs ICMP echo test.
func (d *Diagnostics) Ping(target string, count int) (*PingResult, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	localIP := getLocalIP()
	result := &PingResult{Target: target, Sent: count}

	fmt.Printf("PING %s (%s): %d packets\n", target, ip, count)

	for i := 0; i < count; i++ {
		start := time.Now()
		payload := make([]byte, 56)
		binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))

		err := d.socket.Send(localIP, ip, uint16(i+1), uint16(i+1), payload)
		if err != nil {
			fmt.Printf("  Send error: %v\n", err)
			continue
		}

		d.socket.SetReadDeadline(3 * time.Second)
		_, _, _, _, _, rawBuf, err := d.socket.Receive()
		if err != nil {
			fmt.Printf("  Timeout\n")
			if rawBuf != nil {
				icmp.ReleaseBuffer(rawBuf)
			}
			continue
		}
		icmp.ReleaseBuffer(rawBuf)

		rtt := time.Since(start)
		result.RTTs = append(result.RTTs, rtt)
		result.Received++

		fmt.Printf("  Reply from %s: time=%v\n", ip, rtt.Round(time.Microsecond))
		time.Sleep(1 * time.Second)
	}

	if len(result.RTTs) > 0 {
		result.MinRTT = result.RTTs[0]
		result.MaxRTT = result.RTTs[0]
		var total time.Duration
		for _, rtt := range result.RTTs {
			total += rtt
			if rtt < result.MinRTT {
				result.MinRTT = rtt
			}
			if rtt > result.MaxRTT {
				result.MaxRTT = rtt
			}
		}
		result.AvgRTT = total / time.Duration(len(result.RTTs))
	}
	result.LossRate = float64(result.Sent-result.Received) / float64(result.Sent) * 100

	fmt.Printf("\n--- %s ping statistics ---\n", target)
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
		result.Sent, result.Received, result.LossRate)
	if len(result.RTTs) > 0 {
		fmt.Printf("rtt min/avg/max = %v/%v/%v\n", result.MinRTT, result.AvgRTT, result.MaxRTT)
	}

	return result, nil
}

// ThroughputResult holds results from a throughput test.
type ThroughputResult struct {
	Duration    time.Duration
	BytesSent   int64
	PacketsSent int64
	Throughput  float64 // bytes/sec
}

// Throughput measures ICMP throughput.
func (d *Diagnostics) Throughput(target string, durationSec int) (*ThroughputResult, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	localIP := getLocalIP()
	duration := time.Duration(durationSec) * time.Second
	payload := make([]byte, 1400) // Near-MTU payload
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	fmt.Printf("Throughput test to %s for %v...\n", target, duration)

	result := &ThroughputResult{}
	start := time.Now()
	seq := uint16(0)

	for time.Since(start) < duration {
		seq++
		err := d.socket.Send(localIP, ip, 0x1234, seq, payload)
		if err != nil {
			continue
		}
		result.PacketsSent++
		result.BytesSent += int64(len(payload))
	}

	result.Duration = time.Since(start)
	result.Throughput = float64(result.BytesSent) / result.Duration.Seconds()

	fmt.Printf("Sent %d packets (%d bytes) in %v\n", result.PacketsSent, result.BytesSent, result.Duration)
	fmt.Printf("Throughput: %.2f MB/s (%.2f Mbps)\n",
		result.Throughput/1024/1024, result.Throughput*8/1024/1024)

	return result, nil
}

// PacketLoss measures packet loss rate.
func (d *Diagnostics) PacketLoss(target string, count int) (*PingResult, error) {
	return d.Ping(target, count)
}

// DPIDetectResult holds DPI detection results.
type DPIDetectResult struct {
	Tests []DPITest
}

type DPITest struct {
	Name     string
	Passed   bool
	Details  string
}

// DPIDetect tests for DPI interference.
func (d *Diagnostics) DPIDetect(target string) (*DPIDetectResult, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	result := &DPIDetectResult{}
	localIP := getLocalIP()

	fmt.Printf("DPI detection test to %s...\n\n", target)

	// Test 1: Standard ping
	test := DPITest{Name: "Standard ICMP ping"}
	d.socket.SetReadDeadline(3 * time.Second)
	err := d.socket.Send(localIP, ip, 1, 1, make([]byte, 56))
	if err == nil {
		_, _, _, _, _, rawBuf, recvErr := d.socket.Receive()
		if recvErr == nil {
			test.Passed = true
			test.Details = "Standard ICMP echo works"
			icmp.ReleaseBuffer(rawBuf)
		} else {
			test.Details = "No response to standard ping"
		}
	} else {
		test.Details = fmt.Sprintf("Send failed: %v", err)
	}
	result.Tests = append(result.Tests, test)
	fmt.Printf("  %-30s %s (%s)\n", test.Name, boolStr(test.Passed), test.Details)

	// Test 2: Large payload
	test = DPITest{Name: "Large payload (1400 bytes)"}
	bigPayload := make([]byte, 1400)
	err = d.socket.Send(localIP, ip, 2, 1, bigPayload)
	if err == nil {
		_, _, _, _, _, rawBuf, recvErr := d.socket.Receive()
		if recvErr == nil {
			test.Passed = true
			test.Details = "Large payloads allowed"
			icmp.ReleaseBuffer(rawBuf)
		} else {
			test.Details = "Large payloads may be filtered"
		}
	}
	result.Tests = append(result.Tests, test)
	fmt.Printf("  %-30s %s (%s)\n", test.Name, boolStr(test.Passed), test.Details)

	// Test 3: Rapid fire
	test = DPITest{Name: "Rapid fire (100 pps)"}
	sent, received := 0, 0
	for i := 0; i < 100; i++ {
		err = d.socket.Send(localIP, ip, 3, uint16(i+1), make([]byte, 56))
		if err == nil {
			sent++
		}
	}
	d.socket.SetReadDeadline(2 * time.Second)
	for i := 0; i < 100; i++ {
		_, _, _, _, _, rawBuf, recvErr := d.socket.Receive()
		if recvErr != nil {
			break
		}
		received++
		icmp.ReleaseBuffer(rawBuf)
	}
	test.Passed = received > 50
	test.Details = fmt.Sprintf("%d/%d packets received", received, sent)
	result.Tests = append(result.Tests, test)
	fmt.Printf("  %-30s %s (%s)\n", test.Name, boolStr(test.Passed), test.Details)

	return result, nil
}

// SpoofTest tests ICMP spoofing through a relay.
func (d *Diagnostics) SpoofTest(relay, server string) error {
	fmt.Printf("Spoof test: relay=%s server=%s\n", relay, server)
	fmt.Printf("(Not implemented in diagnostic mode - use full tunnel client)\n")
	return nil
}

// StatusCheck checks tunnel server status.
func (d *Diagnostics) StatusCheck(target string) error {
	ip := net.ParseIP(target)
	if ip == nil {
		return fmt.Errorf("invalid target: %s", target)
	}

	fmt.Printf("Checking tunnel server status at %s...\n", target)

	localIP := getLocalIP()
	diagPkt := &icmp.TunnelPacket{
		Type: icmp.TypeDiag,
		Data: []byte("status"),
	}
	if d.authToken != "" {
		diagPkt.Data = append([]byte(d.authToken), diagPkt.Data...)
	}

	encoded := diagPkt.Encode()
	d.socket.SetReadDeadline(5 * time.Second)
	err := d.socket.Send(localIP, ip, 0xDEAD, 1, encoded)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	_, _, _, _, _, rawBuf, err := d.socket.Receive()
	if err != nil {
		fmt.Printf("Server not responding (may be filtered or not running)\n")
		return nil
	}
	icmp.ReleaseBuffer(rawBuf)
	fmt.Printf("Server responded - tunnel endpoint active\n")
	return nil
}

// StressResult holds stress test results.
type StressResult struct {
	Level         string
	Duration      time.Duration
	TotalPackets  int64
	TotalBytes    int64
	Errors        int64
	AvgThroughput float64
	P50Latency    time.Duration
	P99Latency    time.Duration
}

// StressTest runs a stress test.
func (d *Diagnostics) StressTest(target string, level string, duration time.Duration) (*StressResult, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	localIP := getLocalIP()
	workerCount := 1
	payloadSize := 100

	switch level {
	case "medium":
		workerCount = 4
		payloadSize = 500
	case "high":
		workerCount = 8
		payloadSize = 1400
	}

	fmt.Printf("Stress test: level=%s workers=%d payload=%dB duration=%v\n",
		level, workerCount, payloadSize, duration)

	result := &StressResult{Level: level}
	var mu sync.Mutex
	var latencies []time.Duration
	var wg sync.WaitGroup

	start := time.Now()
	done := time.After(duration)

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			payload := make([]byte, payloadSize)
			seq := uint16(0)

			for {
				select {
				case <-done:
					return
				default:
				}

				seq++
				sendTime := time.Now()
				err := d.socket.Send(localIP, ip, uint16(workerID+1), seq, payload)
				if err != nil {
					mu.Lock()
					result.Errors++
					mu.Unlock()
					continue
				}

				rtt := time.Since(sendTime)
				mu.Lock()
				result.TotalPackets++
				result.TotalBytes += int64(payloadSize)
				latencies = append(latencies, rtt)
				mu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	result.AvgThroughput = float64(result.TotalBytes) / result.Duration.Seconds()

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		p50Idx := int(math.Ceil(float64(len(latencies))*0.50)) - 1
		p99Idx := int(math.Ceil(float64(len(latencies))*0.99)) - 1
		if p50Idx >= 0 && p50Idx < len(latencies) {
			result.P50Latency = latencies[p50Idx]
		}
		if p99Idx >= 0 && p99Idx < len(latencies) {
			result.P99Latency = latencies[p99Idx]
		}
	}

	fmt.Printf("\n--- Stress test results ---\n")
	fmt.Printf("Packets: %d sent, %d errors\n", result.TotalPackets, result.Errors)
	fmt.Printf("Throughput: %.2f MB/s\n", result.AvgThroughput/1024/1024)
	fmt.Printf("Latency: p50=%v p99=%v\n", result.P50Latency, result.P99Latency)

	return result, nil
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func boolStr(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}
