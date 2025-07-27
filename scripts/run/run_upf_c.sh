#!/bin/bash
set -e

# -----------------------------------------
# Start script for UPF-C
# -----------------------------------------

# Check if ONVM manager is running (skip in Docker)
if [[ -z $(pgrep -u root "onvm_mgr") ]] && ! grep -q "docker" /proc/1/cgroup
then
    echo "ERROR: NF cannot start without a running ONVM manager"
    exit 1
fi

# Usage information
function usage {
    echo "Usage:"
    echo "  $0 SERVICE-ID -f UPF-C-CONFIG [remaining NF args]"
    echo "  $0 DPDK_ARGS -- ONVM_ARGS -- NF_ARGS"
    echo ""
    echo "Examples:"
    echo "  $0 1 -f path/to/upfcfg.yaml # Launch UPF-C with service ID 1"
    exit 1
}

# Require at least 2 arguments: service ID + upf_c config
if [ "$#" -lt 2 ]; then
    echo "ERROR: Missing required arguments"
    usage
fi

# Set working directory and default UPF-C path
WORK_DIR=$HOME
DEFAULT_UPF_C_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf/build/5gc/l25gc_upf_c_complete"

# Default DPDK args
DPDK_BASE_ARGS="-n 3 --proc-type=secondary"
DEFAULT_CORE_ID=0

# Verify the NF binary exists
if [ ! -f "$DEFAULT_UPF_C_PATH" ]; then
    echo "ERROR: NF executable not found: $DEFAULT_UPF_C_PATH"
    echo "Make sure the NF binary is built and the script is run from the NF folder"
    exit 1
fi

# --- Handle argument separation using "--" ---
# We expect either:
#   0 separators → simple mode (service ID + upf_c config)
#   2 separators → advanced mode (custom DPDK / ONVM / NF args)
#   1 separator  → invalid usage

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

# --- Advanced mode ---
if [[ $dash_dash_cnt -ge 2 ]]; then
    DPDK_ARGS="$DPDK_BASE_ARGS $(echo " $*" | awk -F "--" '{print $1}')"
    ONVM_ARGS="$(echo " $*" | awk -F "--" '{print $2}')"
    shift ${non_nf_arg_cnt}

    # Warn if using custom core list without -m for ONVM
    if [[ $DPDK_ARGS =~ "-l" && ! $ONVM_ARGS =~ "-m" ]]; then
        echo "Warning: You specified -l (core list) without -m (core mask)."
    fi

# --- Simple mode ---
elif [[ $dash_dash_cnt -eq 0 ]]; then
    service=$1
    shift 1 # Shift out NF_NAME, now "$1" is either -F or args

    DPDK_ARGS="-l $DEFAULT_CORE_ID $DPDK_BASE_ARGS"
    ONVM_ARGS="-r $service"

# --- Invalid usage: one separator only ---
elif [[ $dash_dash_cnt -eq 1 ]]; then
    echo "ERROR: This script requires either 0 or 2 '--' separators"
    usage
fi

# --- Final launch ---
# shellcheck disable=SC2086 to allow unquoted expansion
exec sudo "$DEFAULT_UPF_C_PATH" $DPDK_ARGS -- $ONVM_ARGS -- -f "$@"
