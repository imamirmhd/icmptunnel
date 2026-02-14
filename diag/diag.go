// Package diag provides diagnostics and debugging tools for ICMP tunnel connectivity.
package diag

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/user/icmptunnel/icmp"
	"github.com/user/icmptunnel/logger"
)

// Diagnostics provides various tunnel testing capabilities.
type Diagnostics struct {
	socket *icmp.Socket
	log    *logger.Logger
}

// New creates a new diagnostics instance.
func New() (*Diagnostics, error) {
	sock, err := icmp.NewSocket(1472, 64, 5*time.Second, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &Diagnostics{
		socket: sock,
		log:    logger.Default().WithComponent("diag"),
	}, nil
}

// Close releases resources.
func (d *Diagnostics) Close() {
	d.socket.Close()
}

// PingResult holds the result of a ping test.
type PingResult struct {
	Target    string
	Sent      int
	Received  int
	Lost      int
	MinRTT    time.Duration
	MaxRTT    time.Duration
	AvgRTT    time.Duration
	RTTs      []time.Duration
}

// Ping sends ICMP echo requests to verify connectivity.
func (d *Diagnostics) Ping(target string, count int) (*PingResult, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		addrs, err := net.LookupIP(target)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("resolving %s: %w", target, err)
		}
		targetIP = addrs[0]
	}

	localIP := getLocalIP()
	result := &PingResult{
		Target: target,
		Sent:   count,
	}

	fmt.Printf("PING %s (%s)\n", target, targetIP)

	for i := 0; i < count; i++ {
		// Build ICMP echo request with timestamp
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))

		start := time.Now()
		if err := d.socket.SendEcho(localIP, targetIP, payload); err != nil {
			fmt.Printf("Request %d: send error: %v\n", i+1, err)
			result.Lost++
			continue
		}

		// Wait for reply
		deadline := time.Now().Add(5 * time.Second)
		received := false
		for time.Now().Before(deadline) {
			srcIP, icmpType, _, err := d.socket.Receive()
			if err != nil {
				continue
			}
			if icmpType == 0 && srcIP.Equal(targetIP) {
				rtt := time.Since(start)
				result.RTTs = append(result.RTTs, rtt)
				result.Received++
				received = true

				fmt.Printf("Reply from %s: time=%v\n", srcIP, rtt.Round(time.Microsecond))
				break
			}
		}

		if !received {
			fmt.Printf("Request %d: timeout\n", i+1)
			result.Lost++
		}

		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	// Calculate stats
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

	fmt.Printf("\n--- %s ping statistics ---\n", target)
	fmt.Printf("%d packets sent, %d received, %d lost (%.1f%% loss)\n",
		result.Sent, result.Received, result.Lost,
		float64(result.Lost)/float64(result.Sent)*100)
	if len(result.RTTs) > 0 {
		fmt.Printf("rtt min/avg/max = %v/%v/%v\n",
			result.MinRTT.Round(time.Microsecond),
			result.AvgRTT.Round(time.Microsecond),
			result.MaxRTT.Round(time.Microsecond))
	}

	return result, nil
}

// ThroughputResult holds throughput test results.
type ThroughputResult struct {
	BytesSent     int
	Duration      time.Duration
	Throughput    float64 // bytes per second
	PacketsSent   int
	PacketsRecv   int
}

// Throughput measures the tunnel throughput by sending burst data.
func (d *Diagnostics) Throughput(target string, durationSec int) (*ThroughputResult, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", target)
	}

	localIP := getLocalIP()
	result := &ThroughputResult{}
	testDuration := time.Duration(durationSec) * time.Second
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	fmt.Printf("Throughput test to %s for %v...\n", target, testDuration)

	start := time.Now()
	for time.Since(start) < testDuration {
		if err := d.socket.SendEcho(localIP, targetIP, payload); err != nil {
			continue
		}
		result.BytesSent += len(payload)
		result.PacketsSent++
	}

	result.Duration = time.Since(start)
	result.Throughput = float64(result.BytesSent) / result.Duration.Seconds()

	fmt.Printf("\n--- Throughput Results ---\n")
	fmt.Printf("Duration: %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("Sent: %d packets (%d bytes)\n", result.PacketsSent, result.BytesSent)
	fmt.Printf("Throughput: %.2f KB/s\n", result.Throughput/1024)

	return result, nil
}

// PacketLossResult holds packet loss test results.
type PacketLossResult struct {
	Sent     int
	Received int
	Lost     int
	LossRate float64
}

// PacketLoss measures packet loss over a series of ICMP packets.
func (d *Diagnostics) PacketLoss(target string, count int) (*PacketLossResult, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", target)
	}

	localIP := getLocalIP()
	result := &PacketLossResult{Sent: count}

	fmt.Printf("Packet loss test to %s (%d packets)...\n", target, count)

	for i := 0; i < count; i++ {
		payload := make([]byte, 64)
		binary.BigEndian.PutUint32(payload, uint32(i))

		if err := d.socket.SendEcho(localIP, targetIP, payload); err != nil {
			continue
		}

		// Check for reply
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			srcIP, icmpType, _, err := d.socket.Receive()
			if err != nil {
				continue
			}
			if icmpType == 0 && srcIP.Equal(targetIP) {
				result.Received++
				break
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	result.Lost = result.Sent - result.Received
	if result.Sent > 0 {
		result.LossRate = float64(result.Lost) / float64(result.Sent) * 100
	}

	fmt.Printf("\n--- Packet Loss Results ---\n")
	fmt.Printf("Sent: %d, Received: %d, Lost: %d (%.1f%%)\n",
		result.Sent, result.Received, result.Lost, result.LossRate)

	return result, nil
}

// DPIDetectResult holds DPI detection results.
type DPIDetectResult struct {
	StandardICMP  bool
	LargePayload  bool
	SmallPayload  bool
	RapidBurst    bool
	NonStandard   bool
	Assessment    string
}

// DPIDetect tries various ICMP patterns to detect DPI/firewall interference.
func (d *Diagnostics) DPIDetect(target string) (*DPIDetectResult, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", target)
	}

	localIP := getLocalIP()
	result := &DPIDetectResult{}

	fmt.Printf("DPI detection test against %s...\n\n", target)

	// Test 1: Standard ICMP ping (56 bytes)
	fmt.Print("Test 1: Standard ICMP echo (56 bytes)... ")
	result.StandardICMP = d.testPacket(localIP, targetIP, make([]byte, 56))
	printResult(result.StandardICMP)

	// Test 2: Large payload (1400 bytes)
	fmt.Print("Test 2: Large payload (1400 bytes)... ")
	result.LargePayload = d.testPacket(localIP, targetIP, make([]byte, 1400))
	printResult(result.LargePayload)

	// Test 3: Small payload (4 bytes)
	fmt.Print("Test 3: Small payload (4 bytes)... ")
	result.SmallPayload = d.testPacket(localIP, targetIP, make([]byte, 4))
	printResult(result.SmallPayload)

	// Test 4: Rapid burst (10 packets no delay)
	fmt.Print("Test 4: Rapid burst (10 packets)... ")
	burstOk := 0
	for i := 0; i < 10; i++ {
		if d.testPacket(localIP, targetIP, make([]byte, 56)) {
			burstOk++
		}
	}
	result.RapidBurst = burstOk >= 7
	fmt.Printf("%d/10 received\n", burstOk)

	// Test 5: Non-standard payload (random data)
	fmt.Print("Test 5: Random payload data... ")
	randomPayload := make([]byte, 200)
	for i := range randomPayload {
		randomPayload[i] = byte(i * 13 % 256)
	}
	result.NonStandard = d.testPacket(localIP, targetIP, randomPayload)
	printResult(result.NonStandard)

	// Assessment
	fmt.Println("\n--- Assessment ---")
	if result.StandardICMP && result.LargePayload && result.SmallPayload && result.RapidBurst && result.NonStandard {
		result.Assessment = "No DPI interference detected. All ICMP patterns work."
	} else if !result.StandardICMP {
		result.Assessment = "ICMP is completely blocked. Tunnel cannot operate."
	} else if !result.LargePayload {
		result.Assessment = "Large ICMP packets blocked. Enable fragmentation in evasion config."
	} else if !result.RapidBurst {
		result.Assessment = "Burst rate limiting detected. Enable jitter in evasion config."
	} else if !result.NonStandard {
		result.Assessment = "DPI is inspecting payload content. Enable encryption and mimicry."
	} else {
		result.Assessment = "Partial DPI interference. Enable recommended evasion techniques."
	}
	fmt.Println(result.Assessment)

	return result, nil
}

// SpoofTest verifies that spoofed ICMP packets are forwarded by the relay.
func (d *Diagnostics) SpoofTest(relayAddr, mainServerAddr string) error {
	relayIP := net.ParseIP(relayAddr)
	serverIP := net.ParseIP(mainServerAddr)
	if relayIP == nil || serverIP == nil {
		return fmt.Errorf("invalid addresses")
	}

	fmt.Printf("Spoof test: sending to relay %s with spoofed source %s\n", relayAddr, mainServerAddr)

	payload := []byte("SPOOF_TEST")

	// Send ICMP echo to relay with spoofed source (server IP)
	if err := d.socket.SendEcho(serverIP, relayIP, payload); err != nil {
		fmt.Printf("FAIL: Could not send spoofed packet: %v\n", err)
		return err
	}

	fmt.Println("Spoofed packet sent. Check server for received packet.")
	fmt.Println("If the server receives the packet, the relay supports spoofed source forwarding.")

	return nil
}

// StatusCheck verifies if a tunnel server is alive.
func (d *Diagnostics) StatusCheck(target string) error {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return fmt.Errorf("invalid target: %s", target)
	}

	localIP := getLocalIP()

	// Send a diagnostic tunnel packet
	diagPkt := &icmp.TunnelPacket{
		Type:   icmp.TypeDiag,
		SeqNum: 1,
		Data:   []byte("STATUS_CHECK"),
	}

	fmt.Printf("Checking tunnel server at %s...\n", target)

	if err := d.socket.SendEcho(localIP, targetIP, diagPkt.Encode()); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srcIP, icmpType, payload, err := d.socket.Receive()
		if err != nil {
			continue
		}
		if icmpType == 0 && srcIP.Equal(targetIP) && len(payload) > 0 {
			pkt, err := icmp.DecodeTunnelPacket(payload)
			if err == nil && pkt.Type == icmp.TypeDiag {
				fmt.Printf("Server is ALIVE at %s\n", target)
				return nil
			}
		}
	}

	fmt.Printf("Server at %s did not respond (may not be running or is blocked)\n", target)
	return nil
}

func (d *Diagnostics) testPacket(src, dst net.IP, payload []byte) bool {
	if err := d.socket.SendEcho(src, dst, payload); err != nil {
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srcIP, icmpType, _, err := d.socket.Receive()
		if err != nil {
			continue
		}
		if icmpType == 0 && srcIP.Equal(dst) {
			return true
		}
	}
	return false
}

func printResult(ok bool) {
	if ok {
		fmt.Println("PASS")
	} else {
		fmt.Println("FAIL")
	}
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
