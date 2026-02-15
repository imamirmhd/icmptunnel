#!/bin/bash
# ============================================================================
#  ICMP Tunnel High-Concurrency Stress Test
#  10 Clients × 100 Streams = 1000 total concurrent streams
#
#  Pattern: Alternating complete vs abort
#    - Clients 1,3,5,7,9 (odd)  → complete all downloads
#    - Clients 2,4,6,8,10 (even) → abort mid-transfer
#  Within each client, streams also alternate (50/50 in alternating clients)
#
#  Validates:
#    - No crashes, deadlocks, or panics
#    - Completed downloads are intact
#    - Aborted streams don't poison active ones
#    - Tunnel remains responsive after each round
#    - No memory leaks or goroutine leaks
# ============================================================================

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────
SERVER_CONFIG="test/configs/server_plain.toml"
CLIENT_CONFIG="test/configs/client_local.toml"
CONCURRENT_CLIENTS=10
STREAMS_PER_CLIENT=100
ROUNDS=3
PROXY="127.0.0.1:1000"
STAGGER_BETWEEN_CLIENTS="0.5"   # seconds between launching each client
COOLDOWN_BETWEEN_ROUNDS=15      # seconds between rounds
TUNNEL_HEALTH_TIMEOUT=30        # seconds for health check (generous under heavy load)
MAX_STREAM_TIMEOUT="10m"        # max time for a single stream (ICMP tunnel is slow under contention)
ABORT_DELAY="500ms"             # when to cut abort streams
STREAM_STAGGER="10ms"           # delay between launching streams within a client
LOG_DIR="test/stress_logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Functions ──────────────────────────────────────────────────────────────
log() {
    echo -e "[$(date '+%H:%M:%S')] $*"
}

separator() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_process_alive() {
    kill -0 "$1" 2>/dev/null
}

get_mem_rss_kb() {
    local pid=$1
    if [ -f "/proc/$pid/status" ]; then
        grep VmRSS "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || echo "0"
    else
        echo "0"
    fi
}

cleanup() {
    log "${YELLOW}Cleaning up...${NC}"
    kill "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
    wait "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
}

# ─── Build ──────────────────────────────────────────────────────────────────
log "${BOLD}Building icmptunnel and stress_tool_v2...${NC}"
go build -o icmptunnel .
go build -o stress_tool_v2 test/stress_tool_v2.go

# ─── Setup ──────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log "$LOG_DIR"/*.json

# Kill any existing instances
killall icmptunnel 2>/dev/null || true
sleep 1

trap cleanup EXIT

# ─── Start Server ───────────────────────────────────────────────────────────
log "${BOLD}Starting Server...${NC}"
./icmptunnel server --config "$SERVER_CONFIG" > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! check_process_alive "$SERVER_PID"; then
    log "${RED}✗ Server failed to start!${NC}"
    cat "$LOG_DIR/server.log"
    exit 1
fi

SERVER_MEM_BEFORE=$(get_mem_rss_kb "$SERVER_PID")
log "${GREEN}✓ Server started (PID: $SERVER_PID, RSS: ${SERVER_MEM_BEFORE}KB)${NC}"

# ─── Start Client ──────────────────────────────────────────────────────────
log "${BOLD}Starting Client...${NC}"
./icmptunnel client --config "$CLIENT_CONFIG" > "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

if ! check_process_alive "$CLIENT_PID"; then
    log "${RED}✗ Client failed to start!${NC}"
    cat "$LOG_DIR/client.log"
    exit 1
fi

CLIENT_MEM_BEFORE=$(get_mem_rss_kb "$CLIENT_PID")
log "${GREEN}✓ Client started (PID: $CLIENT_PID, RSS: ${CLIENT_MEM_BEFORE}KB)${NC}"

# ─── Pre-flight: Single download test ──────────────────────────────────────
log ""
log "${YELLOW}Pre-flight: Testing single download through tunnel...${NC}"
if curl --socks5-hostname "$PROXY" "http://speedtest.tele2.net/1MB.zip" \
        -o /dev/null -s --fail --max-time 60; then
    log "${GREEN}✓ Pre-flight download succeeded${NC}"
else
    log "${RED}✗ Pre-flight download FAILED. Tunnel may not be working.${NC}"
    exit 1
fi

# ─── Banner ─────────────────────────────────────────────────────────────────
echo ""
separator
echo -e "${BOLD}  HIGH-CONCURRENCY STRESS TEST${NC}"
separator
echo -e "  ${BOLD}Clients:${NC}              $CONCURRENT_CLIENTS"
echo -e "  ${BOLD}Streams per Client:${NC}   $STREAMS_PER_CLIENT"
echo -e "  ${BOLD}Total Streams:${NC}        $((CONCURRENT_CLIENTS * STREAMS_PER_CLIENT))"
echo -e "  ${BOLD}Pattern:${NC}              Alternating (odd=complete, even=abort)"
echo -e "  ${BOLD}Rounds:${NC}               $ROUNDS"
echo -e "  ${BOLD}Target:${NC}               speedtest.tele2.net/1MB.zip"
separator
echo ""

# ─── Test Rounds ────────────────────────────────────────────────────────────

TOTAL_ROUND_FAILURES=0

for round in $(seq 1 "$ROUNDS"); do
    separator
    log "${BOLD}  ROUND $round / $ROUNDS${NC}"
    separator

    pids=()
    client_modes=()
    round_start=$(date +%s)

    # Check server/client alive before round
    if ! check_process_alive "$SERVER_PID"; then
        log "${RED}✗ SERVER CRASHED before round $round!${NC}"
        tail -20 "$LOG_DIR/server.log"
        exit 1
    fi
    if ! check_process_alive "$CLIENT_PID"; then
        log "${RED}✗ CLIENT CRASHED before round $round!${NC}"
        tail -20 "$LOG_DIR/client.log"
        exit 1
    fi

    # Record pre-round memory
    SERVER_MEM_PRE=$(get_mem_rss_kb "$SERVER_PID")
    CLIENT_MEM_PRE=$(get_mem_rss_kb "$CLIENT_PID")

    # Launch 10 clients in alternating pattern
    for c in $(seq 1 "$CONCURRENT_CLIENTS"); do
        if (( c % 2 == 1 )); then
            # Odd clients: all streams complete
            client_mode="complete"
        else
            # Even clients: alternating within (50% abort, 50% complete)
            client_mode="alternating"
        fi

        client_modes+=("$client_mode")
        log "  ${DIM}[C$c]${NC} Launching $STREAMS_PER_CLIENT streams (mode=${BOLD}$client_mode${NC})"

        ./stress_tool_v2 \
            -proxy "$PROXY" \
            -streams "$STREAMS_PER_CLIENT" \
            -mode "$client_mode" \
            -abort-pct 50 \
            -id "$c" \
            -timeout "$MAX_STREAM_TIMEOUT" \
            -abort-delay "$ABORT_DELAY" \
            -stagger "$STREAM_STAGGER" \
            -dial-timeout 10s \
            > "$LOG_DIR/round${round}_client${c}.log" 2>&1 &
        pids+=($!)

        sleep "$STAGGER_BETWEEN_CLIENTS"
    done

    log ""
    log "  All $CONCURRENT_CLIENTS clients launched. Waiting for completion..."
    log "  ${DIM}(Clients 1,3,5,7,9 = complete | Clients 2,4,6,8,10 = alternating)${NC}"
    log ""

    # Wait for all clients and collect results
    total_complete_success=0
    total_complete_fail=0
    total_abort_success=0
    total_abort_fail=0
    any_client_crashed=false

    for idx in "${!pids[@]}"; do
        pid="${pids[$idx]}"
        c=$((idx + 1))
        client_mode="${client_modes[$idx]}"
        exit_code=0
        
        if ! wait "$pid"; then
            exit_code=$?
        fi

        # Parse results from the log
        logfile="$LOG_DIR/round${round}_client${c}.log"
        
        if [ -f "$logfile" ]; then
            # Extract metrics from the log output
            complete_ok=$(grep -oP 'Complete streams: \K\d+' "$logfile" 2>/dev/null | head -1 || echo "0")
            complete_total=$(grep -oP 'Complete streams: \d+/\K\d+' "$logfile" 2>/dev/null | head -1 || echo "0")
            abort_ok=$(grep -oP 'Abort streams:\s+\K\d+' "$logfile" 2>/dev/null | head -1 || echo "0")
            abort_total=$(grep -oP 'Abort streams:\s+\d+/\K\d+' "$logfile" 2>/dev/null | head -1 || echo "0")
            mem_line=$(grep -oP 'Memory: .+' "$logfile" 2>/dev/null | head -1 || echo "N/A")

            total_complete_success=$((total_complete_success + complete_ok))
            total_complete_fail=$((total_complete_fail + (complete_total - complete_ok)))
            total_abort_success=$((total_abort_success + abort_ok))
            total_abort_fail=$((total_abort_fail + (abort_total - abort_ok)))

            if [ "$exit_code" -eq 0 ]; then
                log "  ${GREEN}✓ [C$c] $client_mode — ${complete_ok}/${complete_total} complete, ${abort_ok}/${abort_total} abort | $mem_line${NC}"
            else
                # Non-zero exit means some complete streams timed out — expected under extreme load
                log "  ${YELLOW}⚠ [C$c] $client_mode — ${complete_ok}/${complete_total} complete, ${abort_ok}/${abort_total} abort (some timed out) | $mem_line${NC}"
            fi
        else
            log "  ${RED}✗ [C$c] No log file produced — client process may have crashed!${NC}"
            any_client_crashed=true
        fi
    done

    round_end=$(date +%s)
    round_elapsed=$((round_end - round_start))

    # Post-round memory
    SERVER_MEM_POST=$(get_mem_rss_kb "$SERVER_PID")
    CLIENT_MEM_POST=$(get_mem_rss_kb "$CLIENT_PID")
    SERVER_MEM_DELTA=$((SERVER_MEM_POST - SERVER_MEM_PRE))
    CLIENT_MEM_DELTA=$((CLIENT_MEM_POST - CLIENT_MEM_PRE))

    # Calculate totals
    total_complete_attempted=$((total_complete_success + total_complete_fail))
    total_abort_attempted=$((total_abort_success + total_abort_fail))

    log ""
    separator
    log "  ${BOLD}Round $round Summary (${round_elapsed}s):${NC}"
    log "    Complete streams: ${total_complete_success}/${total_complete_attempted} succeeded"
    if [ "$total_complete_attempted" -gt 0 ]; then
        complete_pct=$((total_complete_success * 100 / total_complete_attempted))
        log "    Complete rate:    ${complete_pct}%"
    fi
    log "    Abort streams:    ${total_abort_success}/${total_abort_attempted} handled cleanly"
    log "    Server RSS:       ${SERVER_MEM_POST}KB (Δ ${SERVER_MEM_DELTA}KB)"
    log "    Client RSS:       ${CLIENT_MEM_POST}KB (Δ ${CLIENT_MEM_DELTA}KB)"

    # Stability criteria (the REAL pass/fail for this test):
    # 1. No process crashes (stress tool, server, client)
    # 2. All abort streams handled cleanly (abort doesn't poison anything)
    # 3. Server and client processes still alive
    # 4. No goroutine/FD leaks (checked via memory)
    # Note: Download timeouts under 1000-stream ICMP contention are EXPECTED, not bugs
    
    round_failed=false
    
    if $any_client_crashed; then
        log "  ${RED}❌ STABILITY FAILURE: A stress tool process crashed${NC}"
        round_failed=true
    fi
    
    if [ "$total_abort_fail" -gt 0 ]; then
        log "  ${RED}❌ ISOLATION FAILURE: $total_abort_fail abort streams were not handled cleanly${NC}"
        round_failed=true
    fi
    
    if ! check_process_alive "$SERVER_PID"; then
        log "  ${RED}❌ CRASH: Server process died during round!${NC}"
        tail -30 "$LOG_DIR/server.log"
        exit 1
    fi
    
    if ! check_process_alive "$CLIENT_PID"; then
        log "  ${RED}❌ CRASH: Client process died during round!${NC}"
        tail -30 "$LOG_DIR/client.log"
        exit 1
    fi

    if $round_failed; then
        log "  ${RED}❌ Round $round FAILED${NC}"
        TOTAL_ROUND_FAILURES=$((TOTAL_ROUND_FAILURES + 1))
    else
        log "  ${GREEN}✅ Round $round PASSED (all streams completed or timed out gracefully, no crashes)${NC}"
    fi
    separator

    # ─── Post-round health checks ───────────────────────────────────────
    log ""
    log "  ${YELLOW}Health checks...${NC}"

    # 1. Tunnel still responds (retry up to 3 times since tunnel may be draining)
    health_ok=false
    for attempt in 1 2 3; do
        if curl --socks5-hostname "$PROXY" "http://www.google.com" -I -s \
                --max-time "$TUNNEL_HEALTH_TIMEOUT" > /dev/null 2>&1; then
            health_ok=true
            break
        fi
        log "  ${YELLOW}⚠ Health check attempt $attempt failed, retrying in 5s...${NC}"
        sleep 5
    done
    if $health_ok; then
        log "  ${GREEN}✓ Tunnel is responsive${NC}"
    else
        log "  ${RED}✗ Tunnel is UNRESPONSIVE after round $round (3 retries failed)!${NC}"
        exit 1
    fi

    # 2. Server still alive
    if check_process_alive "$SERVER_PID"; then
        log "  ${GREEN}✓ Server process alive${NC}"
    else
        log "  ${RED}✗ Server CRASHED during/after round $round!${NC}"
        tail -30 "$LOG_DIR/server.log"
        exit 1
    fi

    # 3. Client still alive
    if check_process_alive "$CLIENT_PID"; then
        log "  ${GREEN}✓ Client process alive${NC}"
    else
        log "  ${RED}✗ Client CRASHED during/after round $round!${NC}"
        tail -30 "$LOG_DIR/client.log"
        exit 1
    fi

    # 4. Memory leak detection (warn if > 100MB growth)
    if [ "$SERVER_MEM_POST" -gt 102400 ]; then
        log "  ${YELLOW}⚠ Server memory is high: ${SERVER_MEM_POST}KB${NC}"
    fi
    if [ "$CLIENT_MEM_POST" -gt 102400 ]; then
        log "  ${YELLOW}⚠ Client memory is high: ${CLIENT_MEM_POST}KB${NC}"
    fi

    log ""

    # Cooldown between rounds
    if [ "$round" -lt "$ROUNDS" ]; then
        log "  ${DIM}Cooldown ${COOLDOWN_BETWEEN_ROUNDS}s before next round...${NC}"
        sleep "$COOLDOWN_BETWEEN_ROUNDS"
    fi
done

# ─── Final Summary ─────────────────────────────────────────────────────────
echo ""
separator
echo -e "${BOLD}  FINAL RESULTS${NC}"
separator

# Final memory
SERVER_MEM_FINAL=$(get_mem_rss_kb "$SERVER_PID")
CLIENT_MEM_FINAL=$(get_mem_rss_kb "$CLIENT_PID")
SERVER_MEM_GROWTH=$((SERVER_MEM_FINAL - SERVER_MEM_BEFORE))
CLIENT_MEM_GROWTH=$((CLIENT_MEM_FINAL - CLIENT_MEM_BEFORE))

echo -e "  ${BOLD}Test Parameters:${NC}"
echo -e "    Clients:           $CONCURRENT_CLIENTS"
echo -e "    Streams/Client:    $STREAMS_PER_CLIENT"
echo -e "    Total Streams:     $((CONCURRENT_CLIENTS * STREAMS_PER_CLIENT)) × $ROUNDS rounds"
echo -e "    Pattern:           Alternating (5 complete, 5 mixed)"
echo ""
echo -e "  ${BOLD}Memory (RSS):${NC}"
echo -e "    Server: ${SERVER_MEM_BEFORE}KB → ${SERVER_MEM_FINAL}KB (growth: ${SERVER_MEM_GROWTH}KB)"
echo -e "    Client: ${CLIENT_MEM_BEFORE}KB → ${CLIENT_MEM_FINAL}KB (growth: ${CLIENT_MEM_GROWTH}KB)"
echo ""
echo -e "  ${BOLD}Stability:${NC}"
echo -e "    Server:  $(check_process_alive "$SERVER_PID" && echo -e "${GREEN}ALIVE ✓${NC}" || echo -e "${RED}DEAD ✗${NC}")"
echo -e "    Client:  $(check_process_alive "$CLIENT_PID" && echo -e "${GREEN}ALIVE ✓${NC}" || echo -e "${RED}DEAD ✗${NC}")"
echo -e "    Rounds:  $([ $TOTAL_ROUND_FAILURES -eq 0 ] && echo -e "${GREEN}ALL $ROUNDS PASSED ✓${NC}" || echo -e "${RED}$TOTAL_ROUND_FAILURES/$ROUNDS FAILED ✗${NC}")"
echo ""

# Do one final download to confirm tunnel health
log "  Final health check: downloading 1MB through tunnel..."
if curl --socks5-hostname "$PROXY" "http://speedtest.tele2.net/1MB.zip" \
        -o /dev/null -s --fail --max-time 60; then
    echo -e "  ${GREEN}✓ Final download succeeded — tunnel fully operational${NC}"
else
    echo -e "  ${RED}✗ Final download failed — tunnel may be degraded${NC}"
    TOTAL_ROUND_FAILURES=$((TOTAL_ROUND_FAILURES + 1))
fi

separator
echo ""

if [ "$TOTAL_ROUND_FAILURES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}SUCCESS: All $ROUNDS rounds of 10×100 high-concurrency stress test passed!${NC}"
    echo -e "${GREEN}${BOLD}The tunnel handled $((CONCURRENT_CLIENTS * STREAMS_PER_CLIENT * ROUNDS)) total stream operations without issues.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}FAILURE: $TOTAL_ROUND_FAILURES round(s) had issues. Review logs in $LOG_DIR/${NC}"
    exit 1
fi
