#!/bin/bash
# ============================================================================
# ICMP Tunnel Stress Test
# Tests 10 concurrent connections x3 rounds (Phase 1 & 2)
# Downloads a 5MB file from the internet through the SOCKS5 proxy
# ============================================================================

set -euo pipefail

SOCKS_PROXY="127.0.0.1:1000"
FILE_URL="http://speedtest.tele2.net/5MB.zip"
EXPECTED_SIZE=5242880  # 5MB exactly
TEMP_DIR="/tmp/icmp_stress_test"
CURL_TIMEOUT=900       # 15 minutes per download max (ICMP tunnel is slow under high concurrency)
LOG_FILE="$(dirname "$0")/stress_test_results.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo -e "$msg"
    echo "$msg" >> "$LOG_FILE"
}

run_round() {
    local concurrent=$1
    local round=$2
    local round_dir="$TEMP_DIR/c${concurrent}_r${round}"

    mkdir -p "$round_dir"
    rm -f "$round_dir"/*

    log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BOLD}Round $round: $concurrent concurrent connections${NC}"
    log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local start_time=$(date +%s)

    # Launch all downloads in parallel
    local pids=()
    for i in $(seq 1 "$concurrent"); do
        curl --socks5-hostname "$SOCKS_PROXY" \
             "$FILE_URL" \
             -o "$round_dir/file_${i}.zip" \
             --silent \
             --max-time "$CURL_TIMEOUT" \
             --retry 0 \
             --fail \
             2>"$round_dir/err_${i}.log" &
        pids+=($!)
    done

    log "  Launched $concurrent downloads (PIDs: ${pids[0]}..${pids[-1]})"
    log "  Waiting for all downloads to complete..."

    # Wait for all background jobs
    local wait_failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            wait_failed=$((wait_failed + 1))
        fi
    done

    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    log "  All downloads finished in ${elapsed}s (curl failures: $wait_failed)"

    # Verify all files
    local failed=0
    local succeeded=0
    local missing=0
    local wrong_size=0

    for i in $(seq 1 "$concurrent"); do
        local file="$round_dir/file_${i}.zip"
        if [ ! -f "$file" ]; then
            log "  ${RED}✗ file_${i}.zip: MISSING${NC}"
            missing=$((missing + 1))
            failed=$((failed + 1))
            continue
        fi

        local size
        size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        if [ "$size" -ne "$EXPECTED_SIZE" ]; then
            log "  ${RED}✗ file_${i}.zip: SIZE MISMATCH (got $size, expected $EXPECTED_SIZE)${NC}"
            wrong_size=$((wrong_size + 1))
            failed=$((failed + 1))
        else
            succeeded=$((succeeded + 1))
        fi
    done

    TOTAL_TESTS=$((TOTAL_TESTS + concurrent))
    TOTAL_PASSED=$((TOTAL_PASSED + succeeded))
    TOTAL_FAILED=$((TOTAL_FAILED + failed))

    if [ "$failed" -eq 0 ]; then
        log "  ${GREEN}✓ PASSED: All $concurrent files downloaded correctly (${elapsed}s)${NC}"
    else
        log "  ${RED}✗ FAILED: $failed/$concurrent downloads failed (missing=$missing, wrong_size=$wrong_size)${NC}"
        # Show error logs for failed downloads
        for i in $(seq 1 "$concurrent"); do
            local errlog="$round_dir/err_${i}.log"
            if [ -s "$errlog" ]; then
                log "    err_${i}: $(head -1 "$errlog")"
            fi
        done
    fi

    log ""
    return $failed
}

# ============================================================================
# Main
# ============================================================================

echo "" > "$LOG_FILE"
mkdir -p "$TEMP_DIR"

log "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
log "${BOLD}║         ICMP Tunnel Stress Test Starting                ║${NC}"
log "${BOLD}║  File: $FILE_URL  (${EXPECTED_SIZE} bytes)${NC}"
log "${BOLD}║  SOCKS5 Proxy: $SOCKS_PROXY                            ║${NC}"
log "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
log ""

# First verify that the proxy is working with a single connection
log "${YELLOW}Pre-flight check: Testing single download through proxy...${NC}"
PREFLIGHT_FILE="$TEMP_DIR/preflight.zip"
if curl --socks5-hostname "$SOCKS_PROXY" "$FILE_URL" -o "$PREFLIGHT_FILE" \
        --silent --max-time 120 --fail 2>/dev/null; then
    PREFLIGHT_SIZE=$(stat -c%s "$PREFLIGHT_FILE" 2>/dev/null || echo "0")
    if [ "$PREFLIGHT_SIZE" -eq "$EXPECTED_SIZE" ]; then
        log "${GREEN}✓ Pre-flight check passed (downloaded $PREFLIGHT_SIZE bytes)${NC}"
    else
        log "${RED}✗ Pre-flight check FAILED: size=$PREFLIGHT_SIZE, expected=$EXPECTED_SIZE${NC}"
        exit 1
    fi
    rm -f "$PREFLIGHT_FILE"
else
    log "${RED}✗ Pre-flight check FAILED: curl exited with error${NC}"
    exit 1
fi
log ""

# ─── Phase 1: 10 Concurrent x 3 Rounds ────────────────────────────────────
PHASE1_FAILURES=0

log "${BOLD}══════════════════════════════════════════════════════════${NC}"
log "${BOLD}  PHASE 1: 10 Concurrent Connections (3 Rounds)${NC}"
log "${BOLD}══════════════════════════════════════════════════════════${NC}"
log ""

for round in 1 2 3; do
    if ! run_round 10 "$round"; then
        PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
    fi
    # Small pause between rounds to let things settle
    if [ "$round" -lt 3 ]; then
        log "  Pausing 5s before next round..."
        sleep 5
    fi
done

log ""
if [ "$PHASE1_FAILURES" -eq 0 ]; then
    log "${GREEN}${BOLD}PHASE 1 RESULT: ALL 3 ROUNDS PASSED ✓${NC}"
else
    log "${RED}${BOLD}PHASE 1 RESULT: $PHASE1_FAILURES/3 ROUNDS HAD FAILURES ✗${NC}"
fi
log ""

# Pause between phases
log "  Pausing 10s before Phase 2..."
sleep 10

# ─── Phase 2: 10 Concurrent x 3 Rounds ────────────────────────────────────
PHASE2_FAILURES=0

log "${BOLD}══════════════════════════════════════════════════════════${NC}"
log "${BOLD}  PHASE 2: 10 Concurrent Connections (3 Rounds)${NC}"
log "${BOLD}══════════════════════════════════════════════════════════${NC}"
log ""

for round in 1 2 3; do
    if ! run_round 10 "$round"; then
        PHASE2_FAILURES=$((PHASE2_FAILURES + 1))
    fi
    if [ "$round" -lt 3 ]; then
        log "  Pausing 5s before next round..."
        sleep 5
    fi
done

log ""
if [ "$PHASE2_FAILURES" -eq 0 ]; then
    log "${GREEN}${BOLD}PHASE 2 RESULT: ALL 3 ROUNDS PASSED ✓${NC}"
else
    log "${RED}${BOLD}PHASE 2 RESULT: $PHASE2_FAILURES/3 ROUNDS HAD FAILURES ✗${NC}"
fi

# ─── Final Summary ─────────────────────────────────────────────────────────
log ""
log "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
log "${BOLD}║                 FINAL SUMMARY                          ║${NC}"
log "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
log "${BOLD}║  Total Downloads: $TOTAL_TESTS${NC}"
log "${BOLD}║  Passed:          $TOTAL_PASSED${NC}"
log "${BOLD}║  Failed:          $TOTAL_FAILED${NC}"
log "${BOLD}║  Phase 1 (10x3):  $([ $PHASE1_FAILURES -eq 0 ] && echo 'PASS ✓' || echo 'FAIL ✗')${NC}"
log "${BOLD}║  Phase 2 (10x3):  $([ $PHASE2_FAILURES -eq 0 ] && echo 'PASS ✓' || echo 'FAIL ✗')${NC}"
log "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"

# Cleanup
rm -rf "$TEMP_DIR"

if [ "$TOTAL_FAILED" -eq 0 ]; then
    log "${GREEN}${BOLD}ALL TESTS PASSED! Server is stable under load. ✓${NC}"
    exit 0
else
    log "${RED}${BOLD}SOME TESTS FAILED! See details above. ✗${NC}"
    exit 1
fi
