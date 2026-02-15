import socket
import struct
import time
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
TARGET_HOST = "www.google.com"
TARGET_PORT = 80

def send_socks5_handshake(sock):
    # Auth methods: No Auth
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        print(f"SOCKS5 Auth failed: {resp}")
        return False
    
    # Connect
    cmd = b"\x05\x01\x00\x03" + bytes([len(TARGET_HOST)]) + TARGET_HOST.encode() + struct.pack("!H", TARGET_PORT)
    sock.sendall(cmd)
    
    resp = sock.recv(4)
    if resp[1] != 0:
        print(f"SOCKS5 Connect failed: {resp[1]}")
        return False
    
    # Read rest of address (IPv4/IPv6/Domain)
    addr_type = resp[3]
    if addr_type == 1: # IPv4
        sock.recv(4 + 2)
    elif addr_type == 3: # Domain
        l = sock.recv(1)[0]
        sock.recv(l + 2)
    elif addr_type == 4: # IPv6
        sock.recv(16 + 2)
        
    return True

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((PROXY_HOST, PROXY_PORT))
    
    print("Handshaking...")
    if not send_socks5_handshake(s):
        sys.exit(1)
    
    print("Connected via SOCKS5. Starting Telegram simulation.")
    
    # 1. Initial burst (Auth/Hello)
    print("Sending auth burst...")
    s.sendall(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
    time.sleep(0.5)
    
    # 2. Receive response (simulate reading)
    data = s.recv(1024)
    print(f"Received {len(data)} bytes")
    
    # 3. Idle (Chat wait)
    print("Idling for 5 seconds...")
    time.sleep(5)
    
    # 4. Keep-alive ping
    print("Sending keep-alive...")
    s.sendall(b" ") # Dummy packet
    
    # 5. Media burst simulation
    print("Sending media burst (10KB)...")
    burst = b"X" * 10240
    s.sendall(burst)
    
    print("Simulation complete. Telegram behavior mimicked.")
    s.close()
    
except Exception as e:
    print(f"Simulation failed: {e}")
    sys.exit(1)
