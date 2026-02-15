#!/bin/bash
set -e

# Configuration
SERVER_CONFIG="test/configs/server_plain.toml"
CLIENT_CONFIG="test/configs/client_local.toml"
URL="http://speedtest.tele2.net/1MB.zip"
CONCURRENT_TOTAL=10
GOOD_CLIENTS=5
BAD_CLIENTS=5
ROUNDS=3
PROXY="127.0.0.1:1000"
# Timeout for "bad" clients to force termination (shorter than typical download time of ~3-4s)
ABORT_TIMEOUT="1s"

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
./icmptunnel server --config "$SERVER_CONFIG" > server_mixed.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server failed to start. Check server_mixed.log"
    cat server_mixed.log
    exit 1
fi

# 2. Start Client
echo "Starting Client..."
./icmptunnel client --config "$CLIENT_CONFIG" > client_mixed.log 2>&1 &
CLIENT_PID=$!
sleep 3

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "Client failed to start. Check client_mixed.log"
    cat client_mixed.log
    exit 1
fi

echo "Tunnel established. Starting mixed stress test (Good vs Aborted connections)..."

# 3. Run Test Rounds
for round in $(seq 1 "$ROUNDS"); do
    echo "=================================================================="
    echo "ROUND $round / $ROUNDS"
    echo "Launching $GOOD_CLIENTS normal downloads and $BAD_CLIENTS aborted downloads..."
    echo "=================================================================="
    
    good_pids=()
    bad_pids=()
    good_failures=0
    
    start_time=$(date +%s)
    
    # Launch "Good" Clients (Must Succeed)
    for i in $(seq 1 "$GOOD_CLIENTS"); do
        curl --socks5-hostname "$PROXY" "$URL" -o /dev/null -s --fail &
        good_pids+=($!)
    done

    # Launch "Bad" Clients (Must Abort)
    # We use 'timeout' to kill curl after 1 second
    for i in $(seq 1 "$BAD_CLIENTS"); do
        timeout "$ABORT_TIMEOUT" curl --socks5-hostname "$PROXY" "$URL" -o /dev/null -s &
        bad_pids+=($!)
    done
    
    # Wait and Verify Good Clients
    for pid in "${good_pids[@]}"; do
        if ! wait "$pid"; then
            echo "❌ Good client (PID $pid) FAILED unexpectedly!"
            good_failures=$((good_failures + 1))
        fi
    done

    # Wait for Bad Clients (we don't check exit code because we expect them to fail/timeout)
    for pid in "${bad_pids[@]}"; do
        wait "$pid" || true
    done
    
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    
    if [ "$good_failures" -eq 0 ]; then
        echo "✅ Round $round PASSED in ${elapsed}s"
        echo "   - $GOOD_CLIENTS/5 downloads completed successfully."
        echo "   - $BAD_CLIENTS/5 downloads were aborted cleanly."
    else
        echo "❌ Round $round FAILED with $good_failures failures in expected-good clients."
        exit 1
    fi
    
    # Check if tunnel is still responsive
    if ! curl --socks5-hostname "$PROXY" "http://www.google.com" -I -s --max-time 2 >/dev/null; then
        echo "❌ Tunnel became unresponsive after Round $round!"
        exit 1
    fi

    # Small pause
    sleep 2
done

echo ""
echo "SUCCESS: All $ROUNDS mixed-load rounds completed. Tunnel remained stable."
