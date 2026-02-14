# icmptunnel

> Tunnel TCP/UDP traffic through ICMP echo and reply packets to bypass firewalls, captive portals, and DPI systems.

**icmptunnel** encapsulates network traffic inside ICMP packets, making it invisible to firewalls that only inspect TCP/UDP. The client provides a **SOCKS5 proxy** and **TCP/UDP port forwarding** — applications connect normally while all traffic is tunneled over ICMP to a remote server which forwards it to its destination.

## Features

| Feature | Description |
|---------|-------------|
| **SOCKS5 Proxy** | Multiple SOCKS5 listeners with optional username/password authentication |
| **Port Forwarding** | TCP and UDP forwarding rules with configurable listen/destination pairs |
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305, or XOR obfuscation |
| **DPI Evasion** | 6 techniques: fragmentation, padding, jitter, mimicry, checksum manipulation, adaptive sizing |
| **ICMP Spoofing** | Relay-based spoofing for environments where direct ICMP is blocked |
| **Transport Layer** | **NEW!** Sliding window, congestion control (CUBIC-like), SACK, and retransmissions for reliable delivery |
| **Authentication** | Unified token-based validation for both session auth and ICMP connectivity |
| **User-Space ICMP** | Application-level echo replies for reliability when kernel replies are disabled |
| **Diagnostics** | Ping, throughput, packet loss, DPI detection, spoof verification |
| **Service Management** | systemd integration with install, start/stop/restart, logs |
| **TOML Configuration** | Fully configurable via human-readable TOML files |

## Architecture

```
┌──────────────┐                              ┌──────────────┐
│    Client     │        ICMP Tunnel           │    Server     │
│              │  ========================►   │              │
│  SOCKS5 ◄──┐ │  ◄========================   │  ──► TCP/UDP │
│  Forwards ◄┘ │     (Encrypted ICMP)         │    Destinations│
└──────────────┘                              └──────────────┘
```

### With ICMP Spoofing Relay

```
┌────────┐   Spoofed ICMP    ┌───────┐   Echo Reply    ┌────────┐
│ Client  │ ───────────────► │ Relay  │ ──────────────► │ Server  │
│         │ (src=Server IP)  │        │ (to forged src) │         │
│         │ ◄──────────────────────────────────────────│         │
└────────┘       Direct or via Relay response          └────────┘
```

## Quick Start

### 1. Build

```bash
git clone https://github.com/user/icmptunnel
cd icmptunnel
go build -o icmptunnel .
```

### 2. Generate Keys

```bash
# Generate an authentication token
./icmptunnel keygen --token

# Generate an encryption key
./icmptunnel keygen --method aes-256-gcm
```

### 3. Configure

Copy and edit the example configs:

```bash
cp examples/server.toml my-server.toml
cp examples/client.toml my-client.toml
# Edit both files with your token, key, and server IP
```

### 4. Run

```bash
# On the server (requires root)
sudo ./icmptunnel server --config my-server.toml

# On the client (requires root)
sudo ./icmptunnel client --config my-client.toml
```

### 5. Use

Configure your applications to use the SOCKS5 proxy:

```bash
# Example: curl through the tunnel
curl --socks5 127.0.0.1:1080 https://example.com

# Example: Firefox — set SOCKS5 proxy to 127.0.0.1:1080
```

## Commands

| Command | Description |
|---------|-------------|
| `icmptunnel server --config <path>` | Start the tunnel server |
| `icmptunnel client --config <path>` | Start the tunnel client |
| `icmptunnel relay --config <path>` | Start the ICMP relay for spoofing |
| `icmptunnel debug ping <target>` | ICMP connectivity test |
| `icmptunnel debug throughput <target>` | Measure ICMP throughput |
| `icmptunnel debug loss <target>` | Measure packet loss |
| `icmptunnel debug detect <target>` | Detect DPI/firewall interference |
| `icmptunnel debug spoof-test <relay> <server>` | Test spoofing via relay |
| `icmptunnel debug status <target>` | Check if tunnel server is alive |
| `icmptunnel keygen [--token] [--method <m>]` | Generate keys/tokens |
| `icmptunnel install` | Install system-wide |
| `icmptunnel service create <name>` | Create a systemd service |
| `icmptunnel service start\|stop\|restart <name>` | Manage services |
| `icmptunnel service status <name>` | Show service status |
| `icmptunnel service logs <name> [-f]` | View service logs |
| `icmptunnel service list` | List all managed services |
| `icmptunnel service remove <name>` | Remove a service |

## Configuration Reference

### Server Configuration (`server.toml`)

```toml
listen = "0.0.0.0"                    # Bind address
auth_tokens = ["token1", "token2"]     # Authorized client tokens

[icmp]
max_packet_size = 1472    # Max ICMP payload (MTU minus IP header)
ttl = 64                  # IP Time-To-Live
read_timeout = "5s"       # Socket read timeout
write_timeout = "5s"      # Socket write timeout
sequence_start = 0        # Starting ICMP sequence number
id_range = [1, 65535]     # ICMP ID range for packets

[encryption]
enabled = true
method = "aes-256-gcm"    # aes-256-gcm | chacha20-poly1305 | xor
key = "<hex-encoded-key>"

[firewall]
disable_echo_reply = true   # Suppress kernel ICMP echo replies
enable_forwarding = true    # Enable IP forwarding

[evasion.fragmentation]
enabled = false
max_fragment_size = 512     # Max bytes per fragment

[evasion.padding]
enabled = false
min_size = 8                # Minimum random padding bytes
max_size = 64               # Maximum random padding bytes

[evasion.jitter]
enabled = false
min_delay = "10ms"          # Minimum inter-packet delay
max_delay = "100ms"         # Maximum inter-packet delay

[evasion.mimicry]
enabled = false
os_signature = "linux"      # linux | windows | macos

[evasion.checksum]
enabled = false             # Alternate checksum strategies

[evasion.adaptive_size]
enabled = false
min_size = 64               # Minimum packet size
max_size = 1400             # Maximum packet size
step_size = 64              # Size increment per packet

[relay]
enabled = false             # Accept spoofed ICMP packets

[logging]
level = "info"              # debug | info | warn | error
output = "stdout"           # stdout | stderr | /path/to/file
```

### Client Configuration (`client.toml`)

```toml
server_addr = "1.2.3.4"               # Server IP address
auth_token = "<your-token>"           # Authentication token

[icmp]
# Same options as server

[encryption]
# Same options as server (key must match)

# Multiple SOCKS5 proxy listeners
[[socks5]]
listen = "127.0.0.1:1080"             # No authentication

[[socks5]]
listen = "127.0.0.1:1081"
username = "user"                      # RFC 1929 auth
password = "pass"

# Port forwarding rules
[[forwards]]
listen = "127.0.0.1:8080"             # Local listen address
destination = "internal.host:80"       # Remote destination
protocol = "tcp"                       # tcp | udp

[[forwards]]
listen = "127.0.0.1:5353"
destination = "8.8.8.8:53"
protocol = "udp"

[evasion.*]
# Same options as server

[spoof]
enabled = false                        # Enable ICMP spoofing
relay_addr = "198.51.100.1"           # Relay server IP
route_via_relay = false                # Response routing preference

[logging]
# Same options as server
```

### Relay Configuration (`relay.toml`)

```toml
listen = "0.0.0.0"
allowed_sources = []                   # IP/CIDR whitelist (empty = all)
rate_limit = 1000                      # Max packets/sec per source

[logging]
level = "info"
output = "stdout"
```

## Unified Token-Based Ping

The **icmptunnel** server implements a user-space ICMP responder that integrates with the authentication system. This provides a "Secure Ping" mechanism:

- **Auth-Protected Connectivity**: standard ICMP echo requests sent to the server are only answered if the payload contains a valid `auth_token`.
- **Connectivity & Credential Verification**: A successful ping response simultaneously proves that the ICMP path is open and your authentication token is valid.
- **Kernel-Independent Reliability**: When `firewall.disable_echo_reply = true` is set, the server ignores automatic OS replies and instead generates replies directly within the `icmptunnel` service after token validation.
- **Stealth**: Pings with missing or invalid tokens are silently dropped, making the server appear non-existent to unauthorized probes.

To test this manually:
```bash
# Using standard ping (if payload supports custom data)
ping <server-ip> -p $(echo -n "your-token" | xxd -p)
```

## Encryption

| Method | Key Size | Security | Performance |
|--------|----------|----------|-------------|
| `aes-256-gcm` | 32 bytes | ★★★★★ High | ★★★★ Fast (AES-NI) |
| `chacha20-poly1305` | 32 bytes | ★★★★★ High | ★★★★★ Fastest (non-AES-NI) |
| `xor` | Any | ★☆☆☆☆ Obfuscation only | ★★★★★ Minimal overhead |

Generate keys with `icmptunnel keygen --method <method>`. Both client and server must use the **same key and method**.

> ⚠️ XOR is NOT cryptographically secure. Use only when encryption overhead is unacceptable and basic obfuscation suffices.

## DPI Evasion Techniques

### Packet Fragmentation
Splits tunnel payloads into smaller fragments to bypass size-based detection. Each fragment carries a header with fragment ID, index, and total count for reassembly.

### Payload Randomization
Appends random padding bytes (configurable range) to every packet, preventing fixed-size pattern matching. A trailing length byte enables reliable removal.

### Timing Jitter
Introduces random delays between packet transmissions to prevent traffic analysis based on timing regularity. Configurable min/max delay range.

### Protocol Mimicry
Adjusts ICMP headers (TTL, type/code, ID patterns, sequence numbers, payload fill bytes) to match legitimate ping signatures from specific operating systems (Linux, Windows, macOS).

### Checksum Manipulation
Uses alternating checksum computation strategies that produce valid checksums via different code paths, preventing fingerprinting by DPI systems that look for specific checksum implementations.

### Adaptive Packet Sizing
Cycles packet sizes through a configurable range (min→max with step increments), defeating detection rules that match fixed-size ICMP payloads.

## ICMP Spoofing with Relay

For environments where direct ICMP to the server is blocked:

1. **Client** sends ICMP echo request to the **relay server** with the source IP forged to the **main server's IP**
2. The **relay** echoes back to the forged source (the main server)
3. The **main server** receives the packet, extracts the **real client IP** from the payload
4. Server responds either **directly to the client** or **back through the relay**, based on a routing flag embedded in the payload

288: ### Setup
289: 
290: ```bash
291: # On the relay (intermediary server)
292: sudo ./icmptunnel relay --config relay.toml
293: 
294: # Server config: enable relay support
295: # [relay]
296: # enabled = true
297: 
298: # Client config: enable spoofing
299: # [spoof]
300: # enabled = true
301: # relay_addr = "relay-ip"
302: # route_via_relay = false
303: ```
304: 
305: > ⚠️ IP spoofing requires: root privileges, `rp_filter=0` on the client, and a relay that does not drop forged-source packets.
306: 
307: ## Transport Layer & Reliability
308: 
309: **icmptunnel v1.0** introduces a robust userspace transport layer on top of ICMP to guarantee reliable delivery, ordering, and congestion control:
310: 
311: - **Sliding Window**: Allows multiple packets in-flight (default window size: 100), significantly improving throughput over high-latency links.
312: - **Selective Acknowledgment (SACK)**: Receivers report non-contiguous blocks of received packets, allowing the sender to retransmit only the missing data.
313: - **Congestion Control**: Adapts transport speed based on packet loss and RTT, acting similar to TCP CUBIC but tuned for ICMP tunnels.
314: - **Compression**: Real-time DEFLATE/LZ4 style compression to reduce bandwidth usage.
315: - **Connection Resilience**: Automatic heartbeat mechanisms and exponential backoff reconnection strategies ensure the tunnel recovers from temporary outages.
316: 
317: Configure these settings in the `[transport]` section of your config:
318: 
319: ```toml
320: [transport]
321: window_size = 100
322: compression = true
323: retransmission_timeout = "200ms"
324: ```
325: 
326: ## Installation & Service Management

### System Installation

```bash
sudo ./icmptunnel install
```

This will:
- Copy the binary to `/usr/local/bin/icmptunnel`
- Create `/etc/icmptunnel/` for configuration
- Create `/etc/icmptunnel/services/` for service registry

### Creating Services

```bash
# Create a server service
sudo icmptunnel service create my-server \
  --mode server \
  --config /etc/icmptunnel/server.toml

# Create a client service
sudo icmptunnel service create my-client \
  --mode client \
  --config /etc/icmptunnel/client.toml

# Enable on boot
sudo systemctl enable icmptunnel@my-server.service
```

### Managing Services

```bash
icmptunnel service start my-server
icmptunnel service stop my-server
icmptunnel service restart my-server
icmptunnel service status my-server
icmptunnel service logs my-server -f
icmptunnel service list
icmptunnel service remove my-server
```

## Diagnostics

### Connectivity Test
```bash
sudo ./icmptunnel debug ping 1.2.3.4 -c 10
```

### Throughput Measurement
```bash
sudo ./icmptunnel debug throughput 1.2.3.4 -d 10
```

### Packet Loss Detection
```bash
sudo ./icmptunnel debug loss 1.2.3.4 -c 500
```

### DPI/Firewall Detection
```bash
sudo ./icmptunnel debug detect 1.2.3.4
```
Runs 5 tests (standard ping, large/small payloads, rapid burst, random payload) and provides an assessment with recommended evasion settings.

### Spoof Verification
```bash
sudo ./icmptunnel debug spoof-test <relay-ip> <server-ip>
```

### Server Status
```bash
sudo ./icmptunnel debug status 1.2.3.4
```

## Security Considerations

- **Root required**: Raw ICMP sockets need `CAP_NET_RAW` or root privileges
- **Always use encryption**: Without encryption, tunnel data is visible in packet captures
- **Use strong tokens**: Generate tokens with `icmptunnel keygen --token` (256-bit random)
- **Firewall the server**: Only expose ICMP, restrict by source IP if possible
- **Avoid XOR in production**: Use AES-256-GCM or ChaCha20-Poly1305 for real security
- **IP spoofing risks**: Spoofed packets may be dropped by ISP-level BCP38 filtering
- **Rate limiting**: Configure the relay's `rate_limit` to prevent abuse

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `creating raw socket: operation not permitted` | Run with `sudo` or grant `CAP_NET_RAW` |
| Authentication timeout | Verify tokens match between client and server configs |
| No reply from server | Check `firewall.disable_echo_reply = true` on server; verify ICMP is not blocked |
| Large packets dropped | Enable `evasion.fragmentation` with smaller `max_fragment_size` |
| Inconsistent connectivity | Enable `evasion.jitter` to avoid rate limiting |
| DPI blocking traffic | Run `debug detect` to identify issues, enable mimicry + encryption |
| Spoofed packets not arriving | Check `rp_filter` settings; run `debug spoof-test` |
| Service won't start | Check `icmptunnel service logs <name>` for errors |
| Config validation error | Use `--dry-run` flag to validate without starting |

## Project Structure

```
icmptunnel/
├── main.go              # Entry point
├── cmd/                 # CLI commands (cobra)
├── config/              # TOML configuration
├── icmp/                # Raw ICMP socket, packet framing, sessions
├── crypto/              # Encryption (AES, ChaCha20, XOR)
├── auth/                # Token authentication
├── evasion/             # DPI evasion techniques
├── proxy/               # SOCKS5 proxy & port forwarding
├── tunnel/              # Client/server tunnel logic
├── relay/               # Relay server for spoofing
├── diag/                # Diagnostics & debugging
├── service/             # Installation & systemd management
├── logger/              # Structured logging
└── examples/            # Example configuration files
```

## License

MIT License
