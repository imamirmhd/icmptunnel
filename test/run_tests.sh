#!/bin/bash
# Comprehensive test script for icmptunnel
# Tests: no encryption, AES-256-GCM, ChaCha20-Poly1305, XOR, port forwarding, fragmentation

set -e
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
TESTS=""

# Ensure log level is error for performance
sed -i 's/level = "debug"/level = "error"/' test/server.toml test/client.toml

log() { echo "[TEST] $*"; }
pass() { PASS=$((PASS+1)); TESTS="$TESTS\n  ✅ $1"; log "PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TESTS="$TESTS\n  ❌ $1"; log "FAIL: $1"; }

cleanup() {
    if [ -n "$SERVER_PID" ]; then kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null; fi
    if [ -n "$CLIENT_PID" ]; then kill $CLIENT_PID 2>/dev/null; wait $CLIENT_PID 2>/dev/null; fi
    if [ -n "$HTTP_PID" ]; then kill $HTTP_PID 2>/dev/null; wait $HTTP_PID 2>/dev/null; fi
    rm -f test/large_file.bin
    SERVER_PID=""
    CLIENT_PID=""
    HTTP_PID=""
    sleep 1
}

setup_http_server() {
    # Create files of specific sizes
    dd if=/dev/urandom of=test/1k.bin bs=1000 count=1 status=none
    dd if=/dev/urandom of=test/50k.bin bs=1000 count=50 status=none
    dd if=/dev/urandom of=test/500k.bin bs=1000 count=500 status=none
    dd if=/dev/urandom of=test/1m.bin bs=1M count=1 status=none
    dd if=/dev/urandom of=test/5m.bin bs=1M count=5 status=none
    
    # Start python server on port 8000 serving current directory
    python3 -m http.server 8000 > /tmp/http.log 2>&1 &
    HTTP_PID=$!
    sleep 2
}

start_tunnel() {
    local server_cfg="$1"
    local client_cfg="$2"
    local label="$3"
    
    # Cleanup previous tunnel but keep HTTP server
    if [ -n "$SERVER_PID" ]; then kill $SERVER_PID 2>/dev/null; fi
    if [ -n "$CLIENT_PID" ]; then kill $CLIENT_PID 2>/dev/null; fi
    sleep 1
    
    log "Starting tunnel with $label"
    
    ./icmptunnel server --config "$server_cfg" > /tmp/server_test.log 2>&1 &
    SERVER_PID=$!
    sleep 1
    
    ./icmptunnel client --config "$client_cfg" > /tmp/client_test.log 2>&1 &
    CLIENT_PID=$!
    sleep 3
    
    # Check both are still running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log "Server failed to start!"
        cat /tmp/server_test.log | tail -5
        return 1
    fi
    if ! kill -0 $CLIENT_PID 2>/dev/null; then
        log "Client failed to start!"
        cat /tmp/client_test.log | tail -5
        return 1
    fi
    return 0
}

test_download() {
    local label="$1"
    local filename="$2"
    local size="$3"
    local port="${4:-1080}"
    local timeout="${5:-30}"
    
    local result
    log "Downloading $filename ($size bytes)..."
    
    # Request from /test/$filename
    result=$(curl --socks5 127.0.0.1:$port http://127.0.0.1:8000/test/$filename -o /tmp/test_dl.bin --max-time $timeout -s -w "%{http_code}" 2>/dev/null)
    local actual=$(wc -c < /tmp/test_dl.bin 2>/dev/null || echo 0)
    
    if [ "$actual" = "$size" ] && [ "$result" = "200" ]; then
        pass "$label download ($filename)"
    else
        fail "$label download ($filename) - expected $size, got $actual, HTTP $result"
    fi
}

test_upload() {
    local label="$1"
    local port="${2:-1080}"
    
    local result
    result=$(curl --socks5 127.0.0.1:$port http://httpbin.org/post -d "test=icmptunnel_upload_test" --max-time 20 -s 2>/dev/null)
    
    if echo "$result" | grep -q "icmptunnel_upload_test"; then
        pass "$label upload"
    else
        fail "$label upload"
    fi
}

trap cleanup EXIT

setup_http_server

# ============================================
# Test 1: No encryption
# ============================================
log "========================"
log "Test Suite: No Encryption"
log "========================"
if start_tunnel test/server.toml test/client.toml "no encryption"; then
    test_download "NoEncrypt" "1k.bin" 1000 1080 30
    test_download "NoEncrypt" "50k.bin" 50000 1080 30
    test_download "NoEncrypt" "500k.bin" 500000 1080 60
    test_download "NoEncrypt" "1m.bin" 1048576 1080 120
    test_download "NoEncrypt" "5m.bin" 5242880 1080 300
    test_upload "NoEncrypt"
fi

# ============================================
# Test 2: AES-256-GCM encryption
# ============================================
log "========================"
log "Test Suite: AES-256-GCM"
log "========================"
if start_tunnel test/aes_server.toml test/aes_client.toml "AES-256-GCM"; then
    test_download "AES" "1k.bin" 1000 1080 30
    test_download "AES" "500k.bin" 500000 1080 60
    test_download "AES" "5m.bin" 5242880 1080 300
    test_upload "AES"
fi

# ============================================
# Test 3: ChaCha20-Poly1305 encryption
# ============================================
log "========================"
log "Test Suite: ChaCha20-Poly1305"
log "========================"
if start_tunnel test/chacha_server.toml test/chacha_client.toml "ChaCha20-Poly1305"; then
    test_download "ChaCha20" "1k.bin" 1000 1080 30
    test_download "ChaCha20" "1m.bin" 1048576 1080 120
    test_upload "ChaCha20"
fi

# ============================================
# Test 4: XOR obfuscation
# ============================================
log "========================"
log "Test Suite: XOR Obfuscation"
log "========================"
if start_tunnel test/xor_server.toml test/xor_client.toml "XOR obfuscation"; then
    test_download "XOR" "1k.bin" 1000 1080 30
    test_download "XOR" "1m.bin" 1048576 1080 120
    test_upload "XOR"
fi

# ============================================
# Test 5: Forwarding & Fragmentation
# ============================================
log "========================"
log "Test Suite: Forwarding & Fragmentation"
log "========================"
if start_tunnel test/server.toml test/forward_client.toml "port forwarding"; then
    # Test TCP port forward
    # Local port 8080 forwarded to 127.0.0.1:8000 (which is our python server now, better than httpbin)
    # Edit: config points to httpbin.org. Let's keep it or update it?
    # test/forward_client.toml points to httpbin.org:80
    # Let's verify that works
    result=$(curl http://127.0.0.1:8080/get -H "Host: httpbin.org" --max-time 15 -s 2>/dev/null)
    if echo "$result" | grep -q '"Host": "httpbin.org"'; then
        pass "TCP port forward"
    else
        fail "TCP port forward"
    fi
fi

if start_tunnel test/frag_server.toml test/frag_client.toml "fragmentation"; then
    test_download "Frag" "1k.bin" 1000 1082 30
fi

cleanup

# ============================================
# Summary
# ============================================
echo ""
echo "======================================="
echo "  TEST RESULTS: $PASS passed, $FAIL failed"
echo "======================================="
echo -e "$TESTS"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed. Check logs in /tmp/server_test.log and /tmp/client_test.log"
    exit 1
fi
