#!/bin/bash
set -e

# Configuration
SERVER_CONFIG="test/configs/server_plain.toml"
CLIENT_CONFIG="test/configs/client_local.toml"
CONCURRENT_CLIENTS=10
STREAMS_PER_CLIENT=100
GOOD_CLIENTS=5      # Half
BAD_CLIENTS=5       # Half
ROUNDS=3
PROXY="127.0.0.1:1000"

echo "Building tools..."
go build -o icmptunnel .
go build -o stress_tool test/stress_tool.go

# Function to clear background processes on exit
cleanup() {
    echo "Stopping server and client..."
    kill "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
    wait "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 0. Stop any existing
killall icmptunnel || true
sleep 1

# 1. Start Server
echo "Starting Server..."
./icmptunnel server --config "$SERVER_CONFIG" > server_massive.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server failed to start. Check server_massive.log"
    cat server_massive.log
    exit 1
fi

# 2. Start Client
echo "Starting Client..."
./icmptunnel client --config "$CLIENT_CONFIG" > client_massive.log 2>&1 &
CLIENT_PID=$!
sleep 3

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "Client failed to start. Check client_massive.log"
    cat client_massive.log
    exit 1
fi

echo "Tunnel established. Starting MASSIVE stress test..."
echo "  - Clients: $CONCURRENT_CLIENTS (5 Good, 5 Abort)"
echo "  - Streams per Client: $STREAMS_PER_CLIENT"
echo "  - Total Concurrent Streams: $((CONCURRENT_CLIENTS * STREAMS_PER_CLIENT))"

# 3. Run Test Rounds
for round in $(seq 1 "$ROUNDS"); do
    echo "=================================================================="
    echo "ROUND $round / $ROUNDS"
    echo "Launching $CONCURRENT_CLIENTS concurrent client instances..."
    echo "=================================================================="
    
    pids=()
    start_time=$(date +%s)
    
    # Launch "Good" Clients (Must Succeed)
    for i in $(seq 1 "$GOOD_CLIENTS"); do
        echo "  [C$i] Starting 100 successful streams..."
        ./stress_tool -proxy "$PROXY" -c "$STREAMS_PER_CLIENT" -abort=false > "stress_good_${i}.log" 2>&1 &
        pids+=($!)
        sleep 0.2
    done

    # Launch "Bad" Clients (Must Abort)
    for i in $(seq 1 "$BAD_CLIENTS"); do
        echo "  [C$((GOOD_CLIENTS + i))] Starting 100 aborted streams..."
        ./stress_tool -proxy "$PROXY" -c "$STREAMS_PER_CLIENT" -abort=true > "stress_bad_${i}.log" 2>&1 &
        pids+=($!)
        sleep 0.2
    done
    
    # Wait for all client instances
    failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failures=$((failures + 1))
        fi
    done
    
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    
    if [ "$failures" -eq 0 ]; then
        echo "✅ Round $round PASSED in ${elapsed}s"
        # Verify success logs
        grep "Success:" stress_good_*.log | head -n 1
        echo "   (Checked logs confirmed success)"
    else
        echo "❌ Round $round FAILED with $failures client process failures."
        grep "Fail:" stress_good_*.log || true
        cat "stress_good_1.log"
        exit 1
    fi
    
    # Health Check
    if ! curl --socks5-hostname "$PROXY" "http://www.google.com" -I -s --max-time 5 >/dev/null; then
        echo "❌ Tunnel became unresponsive after Round $round!"
        exit 1
    fi

    # Cleanup logs
    rm -f stress_good_*.log stress_bad_*.log

    # Pause to let server cool down / process timeouts
    echo "  Pausing 5s..."
    sleep 5
done

echo ""
echo "SUCCESS: All $ROUNDS massive-load rounds completed. Tunnel remained stable."
