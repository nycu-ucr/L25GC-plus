#!/bin/bash
set -e

# -----------------------------------------
# Start script for Host Agent
# -----------------------------------------

# Check if ONVM manager is running (skip in Docker)
if [[ -z $(pgrep -u root "onvm_mgr") ]] && ! grep -q "docker" /proc/1/cgroup
then
    echo "ERROR: NF cannot start without a running ONVM manager"
    exit 1
fi

usage() {
    echo "Usage:"
    echo "  $0 SERVICE-ID [HOST_AGENT-CONFIG] [HOST_AGENT args]"
    echo "  $0 DPDK_ARGS -- ONVM_ARGS -- HOST_AGENT args"
    echo ""
    echo "Examples:"
    echo "  $0 14"
    echo "  $0 14 ./NFs/onvm-upf/5gc/host_agent/config/host_agent.yaml"
    echo "  $0 14 ./NFs/onvm-upf/5gc/host_agent/config/host_agent.yaml -d 03:00.0 -s dpu_agent"
    exit 1
}

if [ "$#" -lt 1 ]; then
    echo "ERROR: Missing required arguments"
    usage
fi

WORK_DIR=$HOME
DEFAULT_HOST_AGENT_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf/build/5gc/l25gc_host_agent"
DEFAULT_HOST_AGENT_CONFIG_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf/5gc/host_agent/config/host_agent.yaml"
DPDK_BASE_ARGS="-n 3 --proc-type=secondary"
DEFAULT_CORE_ID=14
DEFAULT_SERVICE_ID=14

if [ ! -f "$DEFAULT_HOST_AGENT_PATH" ]; then
    echo "ERROR: NF executable not found: $DEFAULT_HOST_AGENT_PATH"
    echo "Make sure host_agent was built under NFs/onvm-upf before running this script"
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
    DPDK_ARGS="$DPDK_BASE_ARGS $(echo " $*" | awk -F "--" '{print $1}')"
    ONVM_ARGS="$(echo " $*" | awk -F "--" '{print $2}')"
    shift ${non_nf_arg_cnt}

    if [[ $DPDK_ARGS =~ "-l" && ! $ONVM_ARGS =~ "-m" ]]; then
        echo "Warning: You specified -l (core list) without -m (core mask)."
    fi
elif [[ $dash_dash_cnt -eq 0 ]]; then
    service=$1
    shift 1

    if [[ "$service" == -* ]]; then
        echo "INFO: No explicit SERVICE-ID provided; using default $DEFAULT_SERVICE_ID"
        set -- "$service" "$@"
        service=$DEFAULT_SERVICE_ID
    fi

    config_path="$DEFAULT_HOST_AGENT_CONFIG_PATH"
    if [[ "$#" -gt 0 && "$1" != -* ]]; then
        config_path=$1
        shift 1
    fi

    if [ ! -f "$config_path" ]; then
        echo "ERROR: Host Agent config not found: $config_path"
        exit 1
    fi

    DPDK_ARGS="-l $DEFAULT_CORE_ID $DPDK_BASE_ARGS"
    ONVM_ARGS="-r $service -m"
elif [[ $dash_dash_cnt -eq 1 ]]; then
    echo "ERROR: This script requires either 0 or 2 '--' separators"
    usage
fi

# shellcheck disable=SC2086
if [[ $dash_dash_cnt -eq 0 ]]; then
    exec sudo "$DEFAULT_HOST_AGENT_PATH" $DPDK_ARGS -- $ONVM_ARGS -- -f "$config_path" "$@"
else
    exec sudo "$DEFAULT_HOST_AGENT_PATH" $DPDK_ARGS -- $ONVM_ARGS -- "$@"
fi
