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

The `examples/` directory contains several pre-configured scenarios. Choose the one that best matches your network conditions and performance requirements:

```bash
# Example: Using the Basic Tunnel setup
mkdir -p config
cp examples/01-basic-tunnel/*.toml config/
# Edit config/client.toml and config/server.toml with your tokens and IP
```

**Note:** Each scenario folder contains a complete, ready-to-use `client.toml` and `server.toml` pair. Just copy the folder's contents and update the `auth_tokens`, `key`, and `server_addr` fields.

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
| `icmptunnel keygen [--token] [--method <m>]` | Generate keys/tokens |
| `icmptunnel install` | Install system-wide |
| `icmptunnel service create <name>` | Create a systemd service |
| `icmptunnel service start|stop|restart <name>` | Manage services |
| `icmptunnel service logs <name> [-f]` | View service logs |
| `icmptunnel service list` | List all managed services |
| `icmptunnel debug status <target>` | Check if tunnel server is alive |

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

[encryption]
enabled = true
method = "aes-256-gcm"    # aes-256-gcm | chacha20-poly1305 | xor
key = "<hex-encoded-key>"

[firewall]
disable_echo_reply = true   # Suppress kernel ICMP echo replies
enable_forwarding = true    # Enable IP forwarding

[transport]
window_size = 100
compression = true
retransmission_timeout = "200ms"
```

### Client Configuration (`client.toml`)

```toml
server_addr = "1.2.3.4"               # Server IP address
auth_token = "<your-token>"           # Authentication token

[icmp]
# Same options as server

[encryption]
# Same options as server (key must match)

[[socks5]]
listen = "127.0.0.1:1080"             # No authentication

[[forwards]]
listen = "127.0.0.1:8080"             # Local listen address
destination = "internal.host:80"       # Remote destination
protocol = "tcp"                       # tcp | udp
```

## Transport Layer & Reliability

**icmptunnel v1.0** introduces a robust userspace transport layer on top of ICMP to guarantee reliable delivery, ordering, and congestion control:

- **Sliding Window**: Allows multiple packets in-flight (default window size: 100), significantly improving throughput over high-latency links.
- **Selective Acknowledgment (SACK)**: Receivers report non-contiguous blocks of received packets, allowing the sender to retransmit only the missing data.
- **Congestion Control**: Adapts transport speed based on packet loss and RTT, acting similar to TCP CUBIC but tuned for ICMP tunnels.
- **Compression**: Real-time DEFLATE/LZ4 style compression to reduce bandwidth usage.
- **Connection Resilience**: Automatic heartbeat mechanisms and exponential backoff reconnection strategies ensure the tunnel recovers from temporary outages.

## Deployment Scenarios

**icmptunnel** includes several ready-to-use configuration patterns in the `examples/` directory:

### 📁 `01-basic-tunnel`
*   **Best for:** General purpose use.
*   **Details:** Standard ICMP tunnel with SOCKS5 forwarding and minimal evasion.

### 📁 `02-high-performance`
*   **Best for:** Maximum throughput on high-speed reliable links.
*   **Optimizations:** Wide sliding window (`500`) and parallel logical streams.

### 📁 `03-low-latency`
*   **Best for:** Interactive use, SSH, gaming, or voice calls.
*   **Optimizations:** Small sliding window to prevent bufferbloat and fast retransmission timeouts.

### 📁 `04-high-packet-loss`
*   **Best for:** Unreliable satellite links or congested mobile networks.
*   **Optimizations:** Smaller MTU and aggressive retransmissions.

### 📁 `08-dpi-evasion`
*   **Best for:** Bypassing Great Firewalls and high-end traffic analyzers.
*   **Optimizations:** Enables fragmentation, random padding, jitter, and signature mimicry.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `creating raw socket: operation not permitted` | Run with `sudo` or grant `CAP_NET_RAW` |
| Authentication timeout | Verify tokens match between client and server configs |
| No reply from server | Check `firewall.disable_echo_reply = true` on server |
| Large packets dropped | Enable `evasion.fragmentation` with smaller `max_fragment_size` |
| DPI blocking traffic | Run `debug detect` to identify issues, enable mimicry + encryption |
| Config validation error | Use `--dry-run` flag to validate without starting |

## Project Structure

- `cmd/`: Command-line interface definitions
- `config/`: Configuration loading and validation
- `icmp/`: Core ICMP socket and session logic
- `tunnel/`: Client and server tunnel implementations
- `crypto/`: Encryption providers (AES, ChaCha20, XOR)
- `proxy/`: SOCKS5 and port forwarding logic
- `evasion/`: DPI evasion and packet shaping
- `examples/`: Scenario-based configuration templates
