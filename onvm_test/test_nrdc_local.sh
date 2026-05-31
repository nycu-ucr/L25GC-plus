#!/usr/bin/env bash
#
# test-nrdc-local.sh — single-host minimal NR-DC bring-up for L25GC-plus.
#
# Goal: see the new session-local DL FAR code light up in upf_u logs:
#   "DL path upsert: session=<id> ..."
#   "DL path remove: session=<id> ..."
#   "DL path select: session=<id> hash=... far_id=... outer_dst=... teid=... count=..."
#
# Topology (from free-ran-ue/script/namespace-script/free-ran-ue-dc-namespace.sh):
#   host  brHost  10.0.1.1   <-- AMF NGAP listen, UPF-C/U N3 endpoint
#   ns mran-ns    10.0.1.2 / 10.0.2.1   master gNB  (api 40104, xn 31415)
#   ns sran-ns    10.0.1.3 / 10.0.3.1   secondary gNB (api 40104, xn 31415)
#   ns ue-ns      10.0.2.2 / 10.0.3.2   UE
#
# Prerequisites the script does NOT install for you:
#   - L25GC-plus binaries built  (run `make nfs` in L25GC-plus first)
#   - onvm-upf binaries built    (run `make` in NFs/onvm-upf first)
#   - free-ran-ue binary built   (run `make bin` in free-ran-ue first)
#   - DPDK hugepages and ONVM Manager already running (./scripts/run/run_onvm_mgr.sh)
#   - mongodb running, with subscriber 208930000000001 inserted (use webconsole or `make populate`)
#   - sudo access (network namespaces, NIC binding)
#
# What this script does:
#   1) creates the dc-namespaces if missing
#   2) launches CN NFs on the host (amf/smf/...)
#   3) launches UPF-C and UPF-U as ONVM secondaries
#   4) launches master gNB inside mran-ns, secondary gNB inside sran-ns
#   5) launches UE inside ue-ns; UE registers + sets up PDU session
#   6) curl-triggers dynamic NR-DC activation via master gNB API
#   7) tails upf_u.log and asserts the canonical DL-path log strings appear
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
L25GC=${L25GC:-$SCRIPT_DIR}
RAN=${RAN:-$L25GC/free-ran-ue}
if [[ ! -d "$RAN" && -d "$L25GC/../free-ran-ue" ]]; then
    RAN="$L25GC/../free-ran-ue"
fi
LOG=$L25GC/log
mkdir -p "$LOG"
TMPDIR_LOCAL=${TMPDIR_LOCAL:-$L25GC/.tmp}
mkdir -p "$TMPDIR_LOCAL"
GNB_API_HOST_M=10.0.1.2
GNB_API_HOST_S=10.0.1.3
GNB_API_PORT=40104
IMSI="imsi-208930000000001"
ACCESS_IFACE=${ONVM_AF_PACKET_ACCESS_IFACE:-brHost}
CORE_IFACE=${ONVM_AF_PACKET_CORE_IFACE:-brDN}
DN_NS=${DN_NS:-free-dn-ns}
DN_BR=${DN_BR:-brDN}
DN_HOST_IF=${DN_HOST_IF:-dnHost0}
DN_NS_IF=${DN_NS_IF:-dn0}
DN_BR_ADDR=${DN_BR_ADDR:-10.200.0.1/24}
DN_NS_ADDR=${DN_NS_ADDR:-10.200.0.2/24}
GO125=${GO125:-$L25GC/.cache/bin/go1.25.5}
GO_HOME=${GO_HOME:-$L25GC/.cache/home}
GO_MODCACHE=${GO_MODCACHE:-$L25GC/.cache/gomod}
PFCP_WAIT_SECS=${PFCP_WAIT_SECS:-90}
PDU_WAIT_SECS=${PDU_WAIT_SECS:-60}
GNB_WAIT_SECS=${GNB_WAIT_SECS:-12}
GNB_RETRIES=${GNB_RETRIES:-5}
ONVMPOLLER_IPID_YAML=${ONVMPOLLER_IPID_YAML:-$L25GC/onvm_nf_configs/ipid.yaml}
ONVMPOLLER_NFIP_YAML=${ONVMPOLLER_NFIP_YAML:-$L25GC/onvm_nf_configs/NFip.yaml}
ONVMPOLLER_IPID_TXT=${ONVMPOLLER_IPID_TXT:-$L25GC/onvm_nf_configs/ipid.txt}
AMF_CFG="$L25GC/config/amfcfg.yaml"
SMF_CFG="$L25GC/config/smfcfg.yaml"
UPF_C_CFG="$L25GC/NFs/onvm-upf/5gc/upf_c/config/upfcfg.yaml"
UPF_U_CFG="$L25GC/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml"
BACKUP_DIR=
red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
grn() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yel() { printf '\033[0;33m%s\033[0m\n' "$*"; }
require_bin() {
    local p="$1" hint="$2"
    if [[ ! -x "$p" ]]; then
        red "MISSING: $p"
        red "  -> $hint"
        exit 1
    fi
}
step() { echo; yel "==> $*"; }
count_matches() {
    local pattern="$1"
    shift
    grep -ch "$pattern" "$@" 2>/dev/null | awk '{s+=$1} END {print s+0}'
}
launch_gnb_with_retry() {
    local label="$1"
    local ns="$2"
    local cfg="$3"
    local log_file="$4"
    local attempt
    local ready
    local failed

    for attempt in $(seq 1 "$GNB_RETRIES"); do
        rm -f "$log_file" 2>/dev/null || true
        sudo rm -f "$log_file" >/dev/null 2>&1 || true
        echo "  $label gNB attempt $attempt/$GNB_RETRIES"
        sudo -n bash -lc "ip netns exec '$ns' '$RAN/build/free-ran-ue' gnb \
            -c '$cfg' </dev/null > '$log_file' 2>&1 &"

        ready=0
        failed=0
        for _ in $(seq 1 "$GNB_WAIT_SECS"); do
            if grep -q "RAN control plane listener started" "$log_file" 2>/dev/null; then
                ready=1
                break
            fi
            if grep -q "Error connecting to AMF" "$log_file" 2>/dev/null; then
                failed=1
                break
            fi
            sleep 1
        done

        if [[ $ready -eq 1 ]]; then
            grn "  $label gNB ready"
            return 0
        fi

        if [[ $failed -eq 1 ]]; then
            yel "  $label gNB hit AMF connection refusal; retrying"
        else
            yel "  $label gNB did not become ready within ${GNB_WAIT_SECS}s; retrying"
        fi
        sleep 2
    done

    return 1
}
cleanup_local_dn_topology() {
    if [[ "$CORE_IFACE" != "$DN_BR" ]]; then
        return
    fi

    sudo ip netns del "$DN_NS" >/dev/null 2>&1 || true
    sudo ip link del "$DN_BR" >/dev/null 2>&1 || true
    sudo ip link del "$DN_HOST_IF" >/dev/null 2>&1 || true
}

ensure_local_dn_topology() {
    if [[ "$CORE_IFACE" != "$DN_BR" ]]; then
        return
    fi

    cleanup_local_dn_topology

    sudo ip netns add "$DN_NS"
    sudo ip link add "$DN_BR" type bridge
    sudo ip addr add "$DN_BR_ADDR" dev "$DN_BR"
    sudo ip link set "$DN_BR" up

    sudo ip link add "$DN_HOST_IF" type veth peer name "$DN_NS_IF"
    sudo ip link set "$DN_HOST_IF" master "$DN_BR"
    sudo ip link set "$DN_HOST_IF" up
    sudo ip link set "$DN_NS_IF" netns "$DN_NS"

    sudo ip netns exec "$DN_NS" ip link set lo up
    sudo ip netns exec "$DN_NS" ip addr add "$DN_NS_ADDR" dev "$DN_NS_IF"
    sudo ip netns exec "$DN_NS" ip link set "$DN_NS_IF" up
    sudo ip netns exec "$DN_NS" ip route replace 10.60.0.0/16 via 10.200.0.1 dev "$DN_NS_IF"
}

restore_configs() {
    if [[ -z "${BACKUP_DIR:-}" || ! -d "${BACKUP_DIR:-}" ]]; then
        return
    fi

    cp "$BACKUP_DIR/amfcfg.yaml" "$AMF_CFG"
    cp "$BACKUP_DIR/smfcfg.yaml" "$SMF_CFG"
    cp "$BACKUP_DIR/upfcfg.yaml" "$UPF_C_CFG"
    cp "$BACKUP_DIR/upf_u.yaml" "$UPF_U_CFG"
}

stage_local_configs() {
    local master_mac="$1"
    local secondary_mac="$2"
    local dn_mac="$3"
    local amf_tmp
    local smf_tmp
    local upfc_tmp
    local upfu_tmp

    BACKUP_DIR=$(mktemp -d "$TMPDIR_LOCAL/nrdc-config-backup.XXXXXX")
    if [[ -z "$BACKUP_DIR" || ! -d "$BACKUP_DIR" ]]; then
        red "failed to create config backup directory under $TMPDIR_LOCAL"
        exit 1
    fi
    cp "$AMF_CFG" "$BACKUP_DIR/amfcfg.yaml"
    cp "$SMF_CFG" "$BACKUP_DIR/smfcfg.yaml"
    cp "$UPF_C_CFG" "$BACKUP_DIR/upfcfg.yaml"
    cp "$UPF_U_CFG" "$BACKUP_DIR/upf_u.yaml"

    amf_tmp="$BACKUP_DIR/amfcfg.local.yaml"
    smf_tmp="$BACKUP_DIR/smfcfg.local.yaml"
    upfc_tmp="$BACKUP_DIR/upfcfg.local.yaml"
    upfu_tmp="$BACKUP_DIR/upf_u.local.yaml"

    awk '
        /ngapIpList:/ { print; in_ngap=1; next }
        in_ngap && /192\.168\.20\.2/ {
            sub(/192\.168\.20\.2/, "10.0.1.1")
            print
            next
        }
        in_ngap && /192\.168\.30\.2/ { next }
        in_ngap && $0 !~ /^[[:space:]]*-[[:space:]]/ { in_ngap=0 }
        { print }
    ' "$BACKUP_DIR/amfcfg.yaml" > "$amf_tmp"

    sed -E \
        -e 's/192\.168\.21\.2/10.0.1.1/' \
        "$BACKUP_DIR/smfcfg.yaml" > "$smf_tmp"

    sed -E \
        -e 's/(addr: )192\.168\.21\.2/\110.0.1.1/' \
        "$BACKUP_DIR/upfcfg.yaml" > "$upfc_tmp"

    sed -E \
        -e 's/(dn_mac: ).*/\1"'"$dn_mac"'"/' \
        -e 's/(an_mac: ).*/\1"'"$master_mac"'"/' \
        -e 's/(dc_an_mac: ).*/\1"'"$secondary_mac"'"/' \
        -e 's/(dc_gnb_ip: ).*/\1"10.0.1.3"/' \
        -e 's/(dc_upf_ip: ).*/\1"10.0.1.1"/' \
        -e 's/(upf_ip: ).*/\1"10.0.1.1"/' \
        "$BACKUP_DIR/upf_u.yaml" > "$upfu_tmp"

    mv "$amf_tmp" "$AMF_CFG"
    mv "$smf_tmp" "$SMF_CFG"
    mv "$upfc_tmp" "$UPF_C_CFG"
    mv "$upfu_tmp" "$UPF_U_CFG"
}

detect_dn_mac() {
    local gw
    local mac

    if [[ "$CORE_IFACE" == "$DN_BR" ]] && sudo ip netns list | grep -q "^$DN_NS"; then
        sudo ip netns exec "$DN_NS" cat "/sys/class/net/$DN_NS_IF/address"
        return 0
    fi

    gw=$(ip route show default dev "$CORE_IFACE" 2>/dev/null | awk '/default/ {print $3; exit}')
    if [[ -n "$gw" ]]; then
        ping -c 1 -W 1 -I "$CORE_IFACE" "$gw" >/dev/null 2>&1 || true
        mac=$(ip neigh show "$gw" dev "$CORE_IFACE" 2>/dev/null | awk '/lladdr/ {print $5; exit}')
        if [[ -n "$mac" ]]; then
            printf '%s\n' "$mac"
            return 0
        fi
    fi

    awk -F'"' '/dn_mac:/ {print $2; exit}' "$UPF_U_CFG"
}

provision_default_subscriber() {
    local query="db.getSiblingDB(\"free5gc\").subscriptionData.authenticationData.authenticationSubscription.findOne({ueId:\"$IMSI\"})"

    if timeout 5 mongosh --quiet --eval "$query" 2>/dev/null | grep -q "$IMSI"; then
        grn "  subscriber $IMSI already present"
        return 0
    fi

    step "mongo: inserting default subscriber $IMSI"
    (
        cd "$L25GC/onvm_test" && \
        HOME="$GO_HOME" GOMODCACHE="$GO_MODCACHE" GOTOOLCHAIN=local \
        "$GO125" run ./cmd/insert_default_subscriber
    )
}

trap restore_configs EXIT
# ---------------------------------------------------------------------------
# 1. preflight
# ---------------------------------------------------------------------------
step "preflight: checking required binaries"
require_bin "$L25GC/bin/amf"  "cd $L25GC && make nfs"
require_bin "$L25GC/bin/smf"  "cd $L25GC && make nfs"
require_bin "$L25GC/bin/nrf"  "cd $L25GC && make nfs"
require_bin "$L25GC/NFs/onvm-upf/build/5gc/l25gc_upf_u" "cd $L25GC/NFs/onvm-upf && make"
require_bin "$L25GC/NFs/onvm-upf/build/5gc/l25gc_upf_c" "cd $L25GC/NFs/onvm-upf && make"
require_bin "$L25GC/NFs/onvm-upf/build/5gc/l25gc_nrdc_selftest" "cd $L25GC/NFs/onvm-upf && source env/bin/activate && ninja -C build"
require_bin "$GO125" "install Go 1.25.5 into $L25GC/.cache/bin or set GO125=/path/to/go1.25.5"

if [[ ! -x "$RAN/build/free-ran-ue" ]]; then
    step "fallback: free-ran-ue missing, running logic-only NR-DC selftest"
    "$L25GC/NFs/onvm-upf/build/5gc/l25gc_nrdc_selftest" > "$LOG/nrdc-selftest.log" 2>&1

    UPSERTS=$(grep -c "DL path upsert: session=" "$LOG/nrdc-selftest.log" 2>/dev/null || echo 0)
    SELECTS=$(grep -c "DL path select: session=" "$LOG/nrdc-selftest.log" 2>/dev/null || echo 0)
    REMOVES=$(grep -c "DL path remove: session=" "$LOG/nrdc-selftest.log" 2>/dev/null || echo 0)

    echo "  DL path upsert : $UPSERTS"
    echo "  DL path select : $SELECTS"
    echo "  DL path remove : $REMOVES"
    echo
    echo "  --- selftest assertions ---"
    grep -nE "^SELFTEST:" "$LOG/nrdc-selftest.log" || true
    echo
    echo "  --- session-local helper logs ---"
    grep -nE "DL path (upsert|select|remove)" "$LOG/nrdc-selftest.log" || true

    if [[ $UPSERTS -ge 2 && $SELECTS -ge 1 && $REMOVES -ge 1 ]]; then
        grn "PASS: logic-only selftest exercised the real session-local NR-DC code paths."
        exit 0
    fi

    red "FAIL: selftest did not emit the expected NR-DC logs"
    exit 1
fi

require_bin "$RAN/build/free-ran-ue" "cd $RAN && make bin"
grn "  preflight ok"
# ---------------------------------------------------------------------------
# 2. clean previous run
# ---------------------------------------------------------------------------
step "stop: killing any leftover NFs from a previous run"
( cd "$L25GC" && sudo bash scripts/run/stop_cn.sh >/dev/null 2>&1 ) || true
sudo pkill -f free-ran-ue 2>/dev/null || true
sudo rm -f "$LOG"/*.log
cleanup_local_dn_topology
sleep 1
# ---------------------------------------------------------------------------
# 3. namespaces
# ---------------------------------------------------------------------------
step "namespaces: recreating dc namespaces"
( cd "$RAN" && sudo bash script/namespace-script/free-ran-ue-dc-namespace.sh up )
grn "  namespace access bridge for AF_PACKET local test: $ACCESS_IFACE"
# ---------------------------------------------------------------------------
# 4. local core-side DN namespace
# ---------------------------------------------------------------------------
if [[ "$CORE_IFACE" == "$DN_BR" ]]; then
    step "namespaces: creating local DN namespace for core-side traffic"
    ensure_local_dn_topology
    grn "  local DN bridge for AF_PACKET local test: $CORE_IFACE"
fi
# ---------------------------------------------------------------------------
# 5. local config + subscriber prerequisites
# ---------------------------------------------------------------------------
step "config: staging single-host local overrides"
MASTER_AN_MAC=$(sudo ip netns exec free-mran-ns cat /sys/class/net/fnsMRAN/address)
SECONDARY_AN_MAC=$(sudo ip netns exec free-sran-ns cat /sys/class/net/fnsSRAN/address)
DN_MAC=$(detect_dn_mac)
echo "  access iface : $ACCESS_IFACE"
echo "  core iface   : $CORE_IFACE"
echo "  master MAC   : $MASTER_AN_MAC"
echo "  secondary MAC: $SECONDARY_AN_MAC"
echo "  dn MAC       : $DN_MAC"
stage_local_configs "$MASTER_AN_MAC" "$SECONDARY_AN_MAC" "$DN_MAC" || {
    red "failed to stage single-host local configs"
    exit 1
}

step "mongo: ensuring mongod is running"
if ! pgrep -x mongod >/dev/null; then
    sudo systemctl start mongod >/dev/null 2>&1 || true
    sleep 2
fi
if ! pgrep -x mongod >/dev/null; then
    red "mongod is not running and could not be started."
    exit 1
fi
provision_default_subscriber
# ---------------------------------------------------------------------------
# 6. ONVM manager (AF_PACKET local dataplane)
# ---------------------------------------------------------------------------
step "mgr: launching ONVM manager for single-host dataplane"
if ! pgrep -u root onvm_mgr >/dev/null; then
    sudo -n bash -lc "cd '$L25GC' && env ONVM_AF_PACKET_ACCESS_IFACE='$ACCESS_IFACE' \
        ONVM_AF_PACKET_CORE_IFACE='$CORE_IFACE' \
        bash scripts/run/run_onvm_mgr.sh -p ./NFs/onvm-upf -k 3 -n 0xFFF8 -s stdout \
        </dev/null > '$LOG/onvm_mgr.log' 2>&1 &"
    sleep 8
fi
if ! pgrep -u root onvm_mgr >/dev/null; then
    red "onvm_mgr failed to start. Check $LOG/onvm_mgr.log"
    exit 1
fi
# ---------------------------------------------------------------------------
# 7. UPF-C and UPF-U (ONVM secondaries)
# ---------------------------------------------------------------------------
step "upf: launching UPF-C and UPF-U (ONVM secondaries)"
sudo -n bash -lc "cd '$L25GC' && env ONVM_AF_PACKET_ACCESS_IFACE='$ACCESS_IFACE' \
    ONVM_AF_PACKET_CORE_IFACE='$CORE_IFACE' \
    bash scripts/run/run_upf_u.sh 1 NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml \
    </dev/null > '$LOG/upf_u.log' 2>&1 &"
sleep 3
sudo -n bash -lc "cd '$L25GC' && env ONVM_AF_PACKET_ACCESS_IFACE='$ACCESS_IFACE' \
    ONVM_AF_PACKET_CORE_IFACE='$CORE_IFACE' \
    bash scripts/run/run_upf_c.sh 2 NFs/onvm-upf/5gc/upf_c/config/upfcfg.yaml \
    </dev/null > '$LOG/upf_c.log' 2>&1 &"
sleep 3
step "upf: waiting for local UPF processes to finish init"
UPF_READY=0
for _ in $(seq 1 30); do
    if grep -q "Set log level: info" "$LOG/upf_c.log" 2>/dev/null && \
       grep -q "Flow table configured." "$LOG/upf_u.log" 2>/dev/null; then
        UPF_READY=1
        break
    fi
    sleep 1
done
if [[ $UPF_READY -ne 1 ]]; then
    red "UPF processes did not finish init in time."
    echo
    echo "--- tail upf_c.log ---"
    tail -n 40 "$LOG/upf_c.log" 2>/dev/null || true
    echo
    echo "--- tail upf_u.log ---"
    tail -n 40 "$LOG/upf_u.log" 2>/dev/null || true
    exit 1
fi
grn "  UPF processes ready"
# ---------------------------------------------------------------------------
# 8. control-plane NFs on host (staged: NRF -> AMF (verified) -> rest)
# ---------------------------------------------------------------------------
launch_nf_bg() {
    local name="$1"
    local core="$2"
    # match run_cp_nfs.sh: pre-create the log file as root (avoids redirect-perm
    # failures when the host shell is the user but $LOG was made by root) and
    # run the binary via sudo -E with the same env the original script expects.
    sudo install -m 0666 /dev/null "$LOG/${name}.log"
    ( cd "$L25GC" && NF_NAME="$name" sudo -nE env \
        ONVMPOLLER_IPID_YAML="$ONVMPOLLER_IPID_YAML" \
        ONVMPOLLER_NFIP_YAML="$ONVMPOLLER_NFIP_YAML" \
        ONVMPOLLER_IPID_TXT="$ONVMPOLLER_IPID_TXT" \
        taskset -c "$core" "./bin/$name" \
        </dev/null > "$LOG/${name}.log" 2>&1 & )
}

amf_alive_and_listening() {
    sudo ss -lpnA sctp 2>/dev/null | grep -q "10.0.1.1:38412" \
        && pgrep -x amf >/dev/null
}

step "cn: launching NRF (logs: $LOG/nrf.log)"
launch_nf_bg nrf 5
NRF_READY=0
for _ in $(seq 1 20); do
    if grep -qE "SBI server started|Start SBI server|Server starting" "$LOG/nrf.log" 2>/dev/null \
       && pgrep -x nrf >/dev/null; then
        NRF_READY=1; break
    fi
    sleep 1
done
if [[ $NRF_READY -ne 1 ]]; then
    red "NRF did not become ready."
    tail -n 40 "$LOG/nrf.log" 2>/dev/null || true
    exit 1
fi
grn "  NRF ready"

step "cn: launching AMF with stability retry"
AMF_MAX_ATTEMPTS=${AMF_MAX_ATTEMPTS:-3}
AMF_READY=0
for amf_attempt in $(seq 1 "$AMF_MAX_ATTEMPTS"); do
    echo "  AMF attempt $amf_attempt/$AMF_MAX_ATTEMPTS"
    sudo pkill -9 -x amf 2>/dev/null || true
    sleep 1
    launch_nf_bg amf 6

    # wait up to 20s for the SCTP socket to appear with the process alive
    socket_seen=0
    for _ in $(seq 1 20); do
        if amf_alive_and_listening; then socket_seen=1; break; fi
        sleep 1
    done
    if [[ $socket_seen -ne 1 ]]; then
        yel "  AMF did not bind SCTP within 20s; retrying"
        continue
    fi

    # require liveness to hold for 5 more seconds (catches the post-banner crash)
    stable=1
    for _ in $(seq 1 5); do
        sleep 1
        if ! amf_alive_and_listening; then stable=0; break; fi
    done
    if [[ $stable -eq 1 ]]; then
        AMF_READY=1; break
    fi
    yel "  AMF crashed during stability window; retrying"
done
if [[ $AMF_READY -ne 1 ]]; then
    red "AMF N2 SCTP listener did not stabilize after $AMF_MAX_ATTEMPTS attempts."
    echo
    echo "--- tail amf.log ---"
    tail -n 60 "$LOG/amf.log" 2>/dev/null || true
    echo
    echo "--- ss -lpnA sctp ---"
    sudo ss -lpnA sctp 2>/dev/null || true
    echo
    echo "--- pgrep amf ---"
    pgrep -af "^amf|/amf$" 2>/dev/null || echo "  (no amf process)"
    exit 1
fi
grn "  AMF N2 listener ready (sctp-socket, stable)"

step "cn: launching remaining NFs one-by-one"
NF_REMAINING=(smf:7 udr:8 pcf:9 udm:10 nssf:11 ausf:12 chf:13)
for entry in "${NF_REMAINING[@]}"; do
    name="${entry%:*}"
    core="${entry#*:}"
    echo "  starting $name on core $core"
    launch_nf_bg "$name" "$core"
    sleep 2
    if ! amf_alive_and_listening; then
        red "AMF died after launching $name. Tail amf.log + ${name}.log:"
        tail -n 40 "$LOG/amf.log" 2>/dev/null || true
        echo
        tail -n 40 "$LOG/${name}.log" 2>/dev/null || true
        exit 1
    fi
done
grn "  all control-plane NFs launched, AMF still healthy"
# ---------------------------------------------------------------------------
# 10. PFCP association
# ---------------------------------------------------------------------------
step "pfcp: waiting for SMF <-> UPF association"
PFCP_READY=0
for _ in $(seq 1 "$PFCP_WAIT_SECS"); do
    if grep -q "UPF(127.0.0.8) setup association" "$LOG/smf.log" 2>/dev/null; then
        PFCP_READY=1
        break
    fi
    sleep 1
done
if [[ $PFCP_READY -ne 1 ]]; then
    red "PFCP association did not complete before UE attach."
    red "Check $LOG/smf.log and $LOG/upf_c.log"
    echo
    echo "--- tail smf.log ---"
    tail -n 40 "$LOG/smf.log" 2>/dev/null || true
    echo
    echo "--- tail upf_c.log ---"
    tail -n 40 "$LOG/upf_c.log" 2>/dev/null || true
    echo
    echo "--- tail onvm_mgr.log ---"
    tail -n 40 "$LOG/onvm_mgr.log" 2>/dev/null || true
    exit 1
fi
grn "  PFCP association ready"
# ---------------------------------------------------------------------------
# 11. RAN sims
# ---------------------------------------------------------------------------
step "ran: launching master gNB (mran-ns)"
if ! launch_gnb_with_retry "master" "free-mran-ns" \
    "$RAN/config/gnb-dc-dynamic-master.yaml" "$LOG/gnb-master.log"; then
    red "master gNB did not become ready."
    echo
    echo "--- tail gnb-master.log ---"
    tail -n 80 "$LOG/gnb-master.log" 2>/dev/null || true
    echo
    echo "--- tail amf.log ---"
    tail -n 80 "$LOG/amf.log" 2>/dev/null || true
    exit 1
fi
step "ran: launching secondary gNB (sran-ns)"
if ! launch_gnb_with_retry "secondary" "free-sran-ns" \
    "$RAN/config/gnb-dc-dynamic-secondary.yaml" "$LOG/gnb-secondary.log"; then
    red "secondary gNB did not become ready."
    echo
    echo "--- tail gnb-secondary.log ---"
    tail -n 80 "$LOG/gnb-secondary.log" 2>/dev/null || true
    echo
    echo "--- tail amf.log ---"
    tail -n 80 "$LOG/amf.log" 2>/dev/null || true
    exit 1
fi
step "ue: launching UE (ue-ns) — registers + sets up PDU session"
sudo -n bash -lc "ip netns exec free-ue-ns '$RAN/build/free-ran-ue' ue \
    -c '$RAN/config/ue-dc-dynamic.yaml' </dev/null > '$LOG/ue.log' 2>&1 &"
step "ue: waiting for PDU session establishment"
PDU_READY=0
for _ in $(seq 1 "$PDU_WAIT_SECS"); do
    if grep -q "PDU session establishment complete" "$LOG/ue.log" 2>/dev/null; then
        PDU_READY=1
        break
    fi
    sleep 1
done
if [[ $PDU_READY -ne 1 ]]; then
    red "UE did not complete initial PDU session establishment."
    red "Check $LOG/ue.log $LOG/gnb-master.log $LOG/amf.log $LOG/smf.log"
    echo
    echo "--- tail ue.log ---"
    tail -n 40 "$LOG/ue.log" 2>/dev/null || true
    echo
    echo "--- tail gnb-master.log ---"
    tail -n 60 "$LOG/gnb-master.log" 2>/dev/null || true
    echo
    echo "--- tail amf.log ---"
    tail -n 60 "$LOG/amf.log" 2>/dev/null || true
    echo
    echo "--- tail smf.log ---"
    tail -n 60 "$LOG/smf.log" 2>/dev/null || true
    exit 1
fi
grn "  UE PDU session ready"
# ---------------------------------------------------------------------------
# 12. trigger dynamic NR-DC
# ---------------------------------------------------------------------------
step "trigger: POST /api/gnb/ue/nrdc to master gNB ($GNB_API_HOST_M:$GNB_API_PORT)"
TRIGGER_RESP=$(curl -sS -m 10 -X POST \
    "http://$GNB_API_HOST_M:$GNB_API_PORT/api/gnb/ue/nrdc" \
    -H 'Content-Type: application/json' \
    -d "{\"imsi\":\"$IMSI\"}" || true)
echo "  response: $TRIGGER_RESP"
sleep 4                            # SMF → UPF-C PFCP, UPF-C → UPF-U seqlock flip
# ---------------------------------------------------------------------------
# 13. force a few DL packets through UPF-U so 'DL path select' fires
# ---------------------------------------------------------------------------
# 'DL path upsert' fires from UPF-C on the PFCP CreateFAR/UpdateFAR — happens
# automatically at PDU establishment + at NR-DC activation.
#
# 'DL path select' fires from UPF-U packet_handler ONLY when:
#   (a) is_dl && DcEnabled (the global config knob — set when nrdc.dc_gnb_ip
#       is present in upf_u.yaml; verified above)
#   (b) session->dl_paths.count > 1 (i.e. master + DC tunnel both installed)
#   (c) a DL packet actually traverses packet_handler
# So we force DL traffic from the UE side by pinging out:
step "traffic: ping from UE namespace to force DL packets"
if [[ "$CORE_IFACE" == "$DN_BR" ]]; then
    UE_IP=$(awk '/PDU session UE IP:/ {print $NF; exit}' "$LOG/ue.log")
    echo "  dn namespace -> ue ip: $UE_IP"
    sudo bash -lc "ip netns exec '$DN_NS' ping -c 20 -i 0.2 -W 1 '$UE_IP' \
        > '$LOG/dn-ping.log' 2>&1" || true
else
    sudo bash -lc "ip netns exec free-ue-ns ping -c 20 -i 0.2 -W 1 8.8.8.8 \
        > '$LOG/ue-ping.log' 2>&1" || true
fi
sleep 1
# ---------------------------------------------------------------------------
# 14. assertions
# ---------------------------------------------------------------------------
step "assert: looking for new code's log strings in $LOG/upf_*.log"
UPSERTS=$(count_matches "DL path upsert: session=" "$LOG/upf_c.log" "$LOG/upf_u.log")
SELECTS=$(count_matches "DL path select: session=" "$LOG/upf_u.log")
REMOVES=$(count_matches "DL path remove: session=" "$LOG/upf_c.log" "$LOG/upf_u.log")
FINALS=$(count_matches "DC final path:" "$LOG/upf_u.log")
echo "  DL path upsert : $UPSERTS"
echo "  DL path select : $SELECTS"
echo "  DL path remove : $REMOVES"
echo "  DC final path  : $FINALS"
echo
echo "  --- sample 'DL path' lines ---"
grep -nE "DL path (upsert|select|remove)" "$LOG/upf_c.log" "$LOG/upf_u.log" 2>/dev/null | head -8
echo
if [[ $UPSERTS -ge 2 && $SELECTS -ge 1 && $FINALS -ge 1 ]]; then
    grn "PASS: NR-DC end-to-end working AND new session-local code is being exercised."
    grn "      (>=2 upserts means master+DC FARs both registered into dl_paths;"
    grn "       >=1 select means UPF-U hash-picked a DC tunnel for at least 1 DL packet.)"
elif [[ $UPSERTS -ge 1 ]]; then
    yel "PARTIAL: $UPSERTS upserts seen (UPF-C hooking FAR install correctly),"
    yel "         but no 'DL path select' yet. Possible reasons:"
    yel "           - dl_paths.count never reached 2 (NR-DC activation didn't add DC FAR)"
    yel "             → check $LOG/smf.log for 'Activate DCTunnel'"
    yel "           - DcEnabled is 0 (nrdc.dc_gnb_ip not set in upf_u.yaml)"
    yel "             → grep 'NR-DC ECMP enabled' $LOG/upf_u.log"
    yel "           - no DL traffic reached UPF-U (check $LOG/ue-ping.log)"
else
    red "FAIL: no 'DL path' log lines at all. Likely root causes:"
    red "  - UE never registered     (tail -50 $LOG/ue.log)"
    red "  - AMF unreachable from gNB ns (curl mismatch — see Caveat 1 below)"
    red "  - UPF-C never got PFCP    (grep PFCPSession $LOG/upf_c.log)"
    red "  - NR-DC trigger failed    (response above:  $TRIGGER_RESP)"
fi
step "tip: tail logs in another shell:"
echo "  tail -f $LOG/upf_u.log $LOG/upf_c.log $LOG/smf.log"
echo
step "to stop everything:"
echo "  sudo bash $L25GC/scripts/run/stop_cn.sh && sudo pkill -f free-ran-ue"
echo "  sudo bash $RAN/script/namespace-script/free-ran-ue-dc-namespace.sh down"
echo "  sudo iptables -t nat -D PREROUTING -p sctp -d 10.0.1.1 --dport 38412 \\"
echo "      -j DNAT --to-destination 127.0.0.18:38412"
echo
echo "----------------------------------------------------------------"
echo "Caveats (read this before debugging):"
echo "----------------------------------------------------------------"
echo "  C1. nrdc.dc_gnb_ip in upf_u.yaml gates DcEnabled.  Default value"
echo "      is '192.168.31.1' — but our secondary gNB N3 is at 10.0.1.3."
echo "      Edit $L25GC/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml:"
echo "        nrdc:"
echo "          dc_gnb_ip: \"10.0.1.3\""
echo "      otherwise the new code path at upf_u.c:1244 never executes."
echo
echo "  C2. ONVM Manager and hugepages must be set up before this script."
echo "      Quick recipe (once per boot):"
echo "        sudo sysctl -w vm.nr_hugepages=2048"
echo "        sudo mkdir -p /mnt/huge && sudo mount -t hugetlbfs nodev /mnt/huge"
echo "        cd $L25GC && sudo ./scripts/run/run_onvm_mgr.sh"
echo
echo "  C3. MongoDB must be running with subscriber $IMSI provisioned."
echo "      Quick check: mongosh --quiet --eval \"db.getSiblingDB('free5gc').subscriptionData.findOne({ueId:'$IMSI'})\""
