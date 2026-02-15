#!/bin/bash

# Rebuild binaries
echo "Building icmptunnel..."
go build -o icmptunnel main.go

killall icmptunnel || true
sleep 1

LOG_DIR="test_logs"
mkdir -p $LOG_DIR
rm -f $LOG_DIR/*

# Function to run a test
run_test() {
    NAME=$1
    SERVER_CONF=$2
    CLIENT_CONF=$3
    CMD=$4
    
    echo "========================================================"
    echo "Starting Test: $NAME"
    echo "========================================================"
    
    ./icmptunnel server --config test/configs/$SERVER_CONF --log-level info > $LOG_DIR/${NAME}_server_stdout.log 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    ./icmptunnel client --config test/configs/$CLIENT_CONF --log-level info > $LOG_DIR/${NAME}_client_stdout.log 2>&1 &
    CLIENT_PID=$!
    sleep 5
    
    echo "Running payload..."
    eval "$CMD"
    RET=$?
    
    echo "Payload finished with exit code $RET"
    
    kill $CLIENT_PID $SERVER_PID 2>/dev/null
    wait $CLIENT_PID $SERVER_PID 2>/dev/null
    
    if [ $RET -eq 0 ]; then
        echo "TEST RESULT: PASSED"
        return 0
    else
        echo "TEST RESULT: FAILED"
        return 1
    fi
}

# 1. Plain Forwarding
run_test "plain_fwd" "server_plain.toml" "client_forward.toml" \
    "curl -v http://127.0.0.1:8001/10MB.zip -H 'Host: speedtest.tele2.net' -o /dev/null --max-time 60"

# 2. Plain SOCKS5
run_test "plain_socks" "server_plain.toml" "client_plain.toml" \
    "curl -v --socks5-hostname 127.0.0.1:1080 http://speedtest.tele2.net/1MB.zip -o /dev/null --max-time 30"

# 3. Telegram Sim
run_test "telegram_sim" "server_plain.toml" "client_plain.toml" \
    "python3 test/telegram_sim.py"

# 4. Encrypted SOCKS5
run_test "enc_socks" "server_enc.toml" "client_enc.toml" \
    "curl -v --socks5-hostname 127.0.0.1:1081 http://speedtest.tele2.net/1MB.zip -o /dev/null --max-time 30"

echo "Suite complete. Check $LOG_DIR and root logs."
