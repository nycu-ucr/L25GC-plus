#!/usr/bin/env bash
#
# test_nrdc_dual.sh — prove two distinct DL flows can land on different
# NR-DC paths after the single-node stack is up.
#
# Strategy:
#   1) reuse test_nrdc_local.sh to bring the stack up and verify baseline NR-DC
#   2) send one UDP flow to an even destination port
#   3) send one UDP flow to an odd destination port
#   4) verify the new "DC final path" logs for those two flow windows differ
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
L25GC=${L25GC:-$SCRIPT_DIR}
LOG=$L25GC/log
TMPDIR_LOCAL=${TMPDIR_LOCAL:-$L25GC/.tmp}
DN_NS=${DN_NS:-free-dn-ns}
UE_IP=${UE_IP:-}
FLOW_A_PORT=${FLOW_A_PORT:-40000}
FLOW_B_PORT=${FLOW_B_PORT:-40001}
FLOW_A_SPORT=${FLOW_A_SPORT:-41000}
FLOW_B_SPORT=${FLOW_B_SPORT:-41001}
FLOW_PKTS=${FLOW_PKTS:-8}
FLOW_WAIT_SECS=${FLOW_WAIT_SECS:-2}
BOOTSTRAP_LOCAL=${BOOTSTRAP_LOCAL:-1}

mkdir -p "$LOG" "$TMPDIR_LOCAL"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
grn() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yel() { printf '\033[0;33m%s\033[0m\n' "$*"; }
step() { echo; yel "==> $*"; }

require_bin() {
    local name="$1"
    if ! command -v "$name" >/dev/null 2>&1; then
        red "missing required command: $name"
        exit 1
    fi
}

capture_new_lines() {
    local start_line="$1"
    local out_file="$2"
    awk -v start="$start_line" 'NR > start' "$LOG/upf_u.log" > "$out_file"
}

detect_single_path() {
    local file="$1"
    local master_count
    local secondary_count

    master_count=$(grep -c "DC final path: master gNB" "$file" 2>/dev/null || true)
    secondary_count=$(grep -c "DC final path: secondary gNB" "$file" 2>/dev/null || true)

    if [[ "$master_count" -gt 0 && "$secondary_count" -eq 0 ]]; then
        echo "master"
        return 0
    fi

    if [[ "$secondary_count" -gt 0 && "$master_count" -eq 0 ]]; then
        echo "secondary"
        return 0
    fi

    if [[ "$master_count" -eq 0 && "$secondary_count" -eq 0 ]]; then
        echo "none"
        return 0
    fi

    echo "mixed"
}

send_udp_flow() {
    local ue_ip="$1"
    local src_port="$2"
    local dst_port="$3"
    local pkt_count="$4"
    local idx

    for idx in $(seq 1 "$pkt_count"); do
        sudo ip netns exec "$DN_NS" bash -lc \
            "printf 'dual-%s-%s-%s' '$src_port' '$dst_port' '$idx' | \
             nc -u -p '$src_port' -w1 '$ue_ip' '$dst_port' >/dev/null 2>&1 || true"
    done
}

require_bin nc
require_bin sudo
require_bin awk
require_bin wc

if [[ "$BOOTSTRAP_LOCAL" == "1" ]]; then
    step "bootstrap: run baseline single-node NR-DC test"
    bash "$L25GC/test_nrdc_local.sh"
fi

if [[ -z "$UE_IP" ]]; then
    UE_IP=$(awk '/PDU session UE IP:/ {print $NF; exit}' "$LOG/ue.log" 2>/dev/null || true)
fi

if [[ -z "$UE_IP" ]]; then
    red "could not determine UE IP from $LOG/ue.log"
    exit 1
fi

step "dual-flow: send flow A to $UE_IP:$FLOW_A_PORT"
START_A=$(wc -l < "$LOG/upf_u.log")
send_udp_flow "$UE_IP" "$FLOW_A_SPORT" "$FLOW_A_PORT" "$FLOW_PKTS"
sleep "$FLOW_WAIT_SECS"
FLOW_A_LOG=$(mktemp "$TMPDIR_LOCAL/nrdc-dual-flow-a.XXXXXX")
capture_new_lines "$START_A" "$FLOW_A_LOG"
PATH_A=$(detect_single_path "$FLOW_A_LOG")

echo "  flow A path : $PATH_A"
if [[ "$PATH_A" == "none" || "$PATH_A" == "mixed" ]]; then
    red "flow A did not map cleanly to exactly one NR-DC path"
    echo
    echo "--- flow A log slice ---"
    cat "$FLOW_A_LOG"
    exit 1
fi

step "dual-flow: send flow B to $UE_IP:$FLOW_B_PORT"
START_B=$(wc -l < "$LOG/upf_u.log")
send_udp_flow "$UE_IP" "$FLOW_B_SPORT" "$FLOW_B_PORT" "$FLOW_PKTS"
sleep "$FLOW_WAIT_SECS"
FLOW_B_LOG=$(mktemp "$TMPDIR_LOCAL/nrdc-dual-flow-b.XXXXXX")
capture_new_lines "$START_B" "$FLOW_B_LOG"
PATH_B=$(detect_single_path "$FLOW_B_LOG")

echo "  flow B path : $PATH_B"
if [[ "$PATH_B" == "none" || "$PATH_B" == "mixed" ]]; then
    red "flow B did not map cleanly to exactly one NR-DC path"
    echo
    echo "--- flow B log slice ---"
    cat "$FLOW_B_LOG"
    exit 1
fi

if [[ "$PATH_A" == "$PATH_B" ]]; then
    red "dual-flow split was not observed: both flows chose '$PATH_A'"
    echo
    echo "--- flow A log slice ---"
    cat "$FLOW_A_LOG"
    echo
    echo "--- flow B log slice ---"
    cat "$FLOW_B_LOG"
    exit 1
fi

grn "PASS: distinct flows split across both NR-DC paths"
echo "  flow A 4-tuple : 10.200.0.2:$FLOW_A_SPORT -> $UE_IP:$FLOW_A_PORT -> $PATH_A"
echo "  flow B 4-tuple : 10.200.0.2:$FLOW_B_SPORT -> $UE_IP:$FLOW_B_PORT -> $PATH_B"
echo
echo "  --- sample flow A lines ---"
grep -E "DL path select:|DC final path:" "$FLOW_A_LOG" | head -n 6 || true
echo
echo "  --- sample flow B lines ---"
grep -E "DL path select:|DC final path:" "$FLOW_B_LOG" | head -n 6 || true
