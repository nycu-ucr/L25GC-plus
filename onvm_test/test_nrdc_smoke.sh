#!/usr/bin/env bash
#
# test-nrdc-smoke.sh — zero-runtime smoke test for the session-local DL FAR work.
#
# This script does NOT bring up DPDK/ONVM/NFs. It only verifies that the
# implementation is *present in the source tree* and *compiled in*, by checking:
#
#   1. The new struct UpfDlPathSet exists in the right header
#   2. The new helpers (Upsert / Remove / GetByHash / IsDlAccessCandidate) exist
#   3. The PFCP handlers in UPF-C call those helpers
#   4. The new packet_handler block in UPF-U references session->dl_paths
#   5. The expected log format strings are present, verbatim
#   6. (Optional) ELF binaries contain the format strings, proving the build is fresh
#
# Run as:  bash test-nrdc-smoke.sh
# Exits 0 on PASS, non-zero on any missing piece.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
L25GC=${L25GC:-$SCRIPT_DIR}
UPF=$L25GC/NFs/onvm-upf
red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
grn() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yel() { printf '\033[0;33m%s\033[0m\n' "$*"; }
PASS=0; FAIL=0
check() {
    local name="$1" cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        grn "  PASS  $name"
        PASS=$((PASS+1))
    else
        red "  FAIL  $name"
        red "        cmd: $cmd"
        FAIL=$((FAIL+1))
    fi
}
yel "=== 1. struct + flags in header ==="
check "UpfDlPathSet struct in upf_context.h" \
    "grep -q 'UpfDlPathSet' $UPF/onvm/upf/upf_context.h"
check "MAX_DL_PATHS macro" \
    "grep -qE 'MAX_DL_PATHS' $UPF/onvm/upf/upf_context.h"
check "UpfSession has dl_paths field" \
    "grep -qE 'UpfDlPathSet[[:space:]]+dl_paths' $UPF/onvm/upf/upf_context.h"
yel "=== 2. helpers in upf_context.{c,h} ==="
check "UpfFarIsDlAccessCandidate prototype"          "grep -q 'UpfFarIsDlAccessCandidate' $UPF/onvm/upf/upf_context.h"
check "UpfSessionUpsertDlPathFromFar definition"     "grep -q 'UpfSessionUpsertDlPathFromFar(UpfSession' $UPF/onvm/upf/upf_context.c"
check "UpfSessionRemoveDlPathByFarID definition"     "grep -q 'UpfSessionRemoveDlPathByFarID(UpfSession' $UPF/onvm/upf/upf_context.c"
check "UpfSessionGetDlPathByHash definition"         "grep -q 'UpfSessionGetDlPathByHash(const UpfSession' $UPF/onvm/upf/upf_context.c"
yel "=== 3. PFCP-side hooks in upf_c handler ==="
check "Upsert called from PFCP CreateFAR/UpdateFAR" \
    "grep -c 'UpfSessionUpsertDlPathFromFar' $UPF/5gc/upf_c/n4_onvm_pfcp_handler.c | xargs -I{} test {} -ge 2"
check "Remove called from PFCP RemoveFAR" \
    "grep -q 'UpfSessionRemoveDlPathByFarID' $UPF/5gc/upf_c/n4_onvm_pfcp_handler.c"
yel "=== 4. UPF-U fast path uses dl_paths ==="
check "packet_handler reads session->dl_paths.count" \
    "grep -q 'session->dl_paths.count' $UPF/5gc/upf_u/upf_u.c"
check "packet_handler calls UpfSessionGetDlPathByHash" \
    "grep -q 'UpfSessionGetDlPathByHash' $UPF/5gc/upf_u/upf_u.c"
yel "=== 5. canonical log format strings ==="
check "'DL path upsert' format" \
    "grep -q 'DL path upsert: session=' $UPF/onvm/upf/upf_context.c"
check "'DL path remove' format" \
    "grep -q 'DL path remove: session=' $UPF/onvm/upf/upf_context.c"
check "'DL path select' format"  \
    "grep -q 'DL path select: session=' $UPF/5gc/upf_u/upf_u.c"
yel "=== 6. (optional) compiled binary contains the strings ==="
UPF_U_BIN=$UPF/build/5gc/l25gc_upf_u
UPF_C_BIN=$UPF/build/5gc/l25gc_upf_c
if [[ -x "$UPF_U_BIN" && -x "$UPF_C_BIN" ]]; then
    check "upf_u binary contains 'DL path select'" \
        "strings '$UPF_U_BIN' | grep -q 'DL path select: session='"
    check "upf_c binary contains 'DL path upsert'" \
        "strings '$UPF_C_BIN' | grep -q 'DL path upsert: session='"
else
    yel "  SKIP  binaries not built — run: cd $UPF && make"
fi
echo
if [[ $FAIL -eq 0 ]]; then
    grn "ALL CHECKS PASSED ($PASS passed, 0 failed)"
    grn "  → run bash ./test_nrdc_local.sh to actually exercise the new code at runtime."
    exit 0
else
    red "$FAIL CHECK(S) FAILED ($PASS passed)"
    exit 1
fi
