#!/bin/bash
set -e

# Configuration
SERVER_CONFIG="test/configs/server_plain.toml"
CLIENT_CONFIG="test/configs/client_local.toml"
URL="http://speedtest.tele2.net/1MB.zip"
CONCURRENT=5
ROUNDS=3
PROXY="127.0.0.1:1000"

echo "Building icmptunnel..."
go build -o icmptunnel .

# Function to clear background processes on exit
cleanup() {
    echo "Stopping server and client..."
    kill "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
    wait "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Start Server
echo "Starting Server..."
./icmptunnel server --config "$SERVER_CONFIG" > server_test.log 2>&1 &
SERVER_PID=$!
sleep 2

# Check if server is still running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server failed to start. Check server_test.log"
    cat server_test.log
    exit 1
fi

# 2. Start Client
echo "Starting Client..."
./icmptunnel client --config "$CLIENT_CONFIG" > client_test.log 2>&1 &
CLIENT_PID=$!
sleep 3

# Check if client is still running
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "Client failed to start. Check client_test.log"
    cat client_test.log
    exit 1
fi

echo "Tunnel established. Starting test..."

# 3. Run Test Rounds
for round in $(seq 1 "$ROUNDS"); do
    echo "========================================="
    echo "ROUND $round / $ROUNDS"
    echo "Starting $CONCURRENT concurrent downloads..."
    echo "========================================="
    
    pids=()
    failures=0
    
    start_time=$(date +%s)
    
    for i in $(seq 1 "$CONCURRENT"); do
        # Using the exact command requested by user, but in background
        curl --socks5-hostname "$PROXY" "$URL" -o /dev/null -s --fail &
        pids+=($!)
    done
    
    # Wait for completion
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failures=$((failures + 1))
        fi
    done
    
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    
    if [ "$failures" -eq 0 ]; then
        echo "Round $round PASSED in ${elapsed}s"
    else
        echo "Round $round FAILED with $failures failures"
        exit 1
    fi
    
    # Small pause between rounds (optional but good for stability)
    sleep 2
done

echo ""
echo "SUCCESS: All $ROUNDS rounds completed without errors."
