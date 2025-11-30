#!/bin/bash
set -e

# -----------------------------------------
# Start script for UPF-U (ingress/egress role)
# -----------------------------------------
#
# Usage:
#   ./run_upf_u_role.sh ROLE SERVICE-ID UPF-U-CONFIG [remaining NF args]
#   ./run_upf_u_role.sh ROLE DPDK_ARGS -- ONVM_ARGS -- NF_ARGS
#
# Examples:
#   ./run_upf_u_role.sh ingress 1  ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
#   ./run_upf_u_role.sh egress  14 ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
#
# ROLE must be one of: ingress | egress

# Check if ONVM manager is running (skip in Docker)
if [[ -z $(pgrep -u root "onvm_mgr") ]] && ! grep -q "docker" /proc/1/cgroup
then
    echo "ERROR: NF cannot start without a running ONVM manager"
    exit 1
fi

usage() {
    echo "Usage:"
    echo "  $0 ROLE SERVICE-ID UPF-U-CONFIG [remaining NF args]"
    echo "  $0 ROLE DPDK_ARGS -- ONVM_ARGS -- NF_ARGS"
    echo ""
    echo "ROLE:"
    echo "  ingress  - start UPF-U ingress NF (default core: 3)"
    echo "  egress   - start UPF-U egress NF  (default core: 14)"
    echo ""
    echo "Examples:"
    echo "  $0 ingress 1  ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml"
    echo "  $0 egress  14 ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml"
    exit 1
}

if [ "$#" -lt 3 ]; then
    echo "ERROR: Missing required arguments"
    usage
fi

ROLE=$1
shift 1

WORK_DIR=$HOME

case "$ROLE" in
    ingress)
        DEFAULT_UPF_U_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf/build/5gc/l25gc_upf_ingress"
        DEFAULT_SERVICE_ID=1
        ROLE_DEFAULT_CORE_ID=3   # ingress on core 3
        ;;
    egress)
        DEFAULT_UPF_U_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf/build/5gc/l25gc_upf_egress"
        DEFAULT_SERVICE_ID=14
        ROLE_DEFAULT_CORE_ID=14  # egress on core 14
        ;;
    *)
        echo "ERROR: Invalid ROLE '$ROLE' (expected 'ingress' or 'egress')"
        usage
        ;;
esac

if [ "$#" -lt 2 ]; then
    echo "ERROR: Missing required arguments after ROLE"
    usage
fi

DPDK_BASE_ARGS="-n 3 --proc-type=secondary"

if [ ! -f "$DEFAULT_UPF_U_PATH" ]; then
    echo "ERROR: NF executable not found: $DEFAULT_UPF_U_PATH"
    echo "Make sure the NF binary is built (ingress/egress split) before running this script"
    exit 1
fi

dash_dash_cnt=0
non_nf_arg_cnt=0
for i in "$@" ; do
    if [[ $dash_dash_cnt -lt 2 ]]; then
        non_nf_arg_cnt=$((non_nf_arg_cnt + 1))
    fi
    if [[ "$i" == "--" ]]; then
        dash_dash_cnt=$((dash_dash_cnt + 1))
    fi
done

if [[ $dash_dash_cnt -ge 2 ]]; then
    # Advanced mode: ROLE DPDK_ARGS -- ONVM_ARGS -- NF_ARGS
    DPDK_ARGS="$DPDK_BASE_ARGS $(echo " $*" | awk -F "--" '{print $1}')"
    ONVM_ARGS="$(echo " $*" | awk -F "--" '{print $2}')"
    shift ${non_nf_arg_cnt}

    if [[ $DPDK_ARGS =~ "-l" && ! $ONVM_ARGS =~ "-m" ]]; then
        echo "Warning: You specified -l (core list) without -m (core mask)."
    fi

elif [[ $dash_dash_cnt -eq 0 ]]; then
    # Simple mode: ROLE SERVICE-ID UPF-U-CONFIG [...]
    service=$1
    shift 1

    if [[ "$service" == -* ]]; then
        echo "INFO: No explicit SERVICE-ID provided; using default for ROLE '$ROLE': $DEFAULT_SERVICE_ID"
        set -- "$service" "$@"
        service=$DEFAULT_SERVICE_ID
    fi

    # Use per-role default core here
    DPDK_ARGS="-l $ROLE_DEFAULT_CORE_ID $DPDK_BASE_ARGS"
    ONVM_ARGS="-r $service"

else
    echo "ERROR: This script requires either 0 or 2 '--' separators after ROLE"
    usage
fi

# Final launch
# shellcheck disable=SC2086
# exec sudo "$DEFAULT_UPF_U_PATH" $DPDK_ARGS -- $ONVM_ARGS -- "$@"

if [[ -n "$GDB" ]]; then
    echo "[run_upf_u_role] Starting UPF-U under gdb"
    exec sudo gdb --args "$DEFAULT_UPF_U_PATH" $DPDK_ARGS -- $ONVM_ARGS -- "$@"
else
    exec sudo "$DEFAULT_UPF_U_PATH" $DPDK_ARGS -- $ONVM_ARGS -- "$@"
fi