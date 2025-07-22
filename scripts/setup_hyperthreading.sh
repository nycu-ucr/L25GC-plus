#!/bin/bash
set -e

# -------------------------------------------
# Script to enable or disable Hyper-Threading
# -------------------------------------------

usage() {
    echo "Usage: $0 [enable|disable]"
    echo
    echo "  enable   : Brings online the hyperthreaded sibling CPUs"
    echo "  disable  : Offlines the hyperthreaded sibling CPUs"
    echo
    echo "Example:"
    echo "  $0 disable"
    exit 1
}

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run this script as root or with sudo."
    exit 1
fi

if [ "$#" -ne 1 ]; then
    usage
fi

ACTION=$1
if [[ "$ACTION" != "enable" && "$ACTION" != "disable" ]]; then
    usage
fi

echo "[INFO] Requested action: $ACTION"
echo "[INFO] Scanning sibling threads (Hyper-Threads)..."

# Identify CPUs that are considered sibling threads
CPUS_TO_SKIP=" $(cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | sed 's/[^0-9].*//' | sort | uniq | tr "\n" " ") "

# Loop through all CPU cores
for CPU_PATH in /sys/devices/system/cpu/cpu[0-9]*; do
    CPU_ID="$(basename "$CPU_PATH" | tr -cd '0-9')"

    # Skip CPUs in the unique list (one per sibling group)
    if echo "$CPUS_TO_SKIP" | grep -q " $CPU_ID "; then
        continue
    fi

    # Perform action
    if [ "$ACTION" == "disable" ]; then
        echo "[INFO] Offlining hyperthreaded CPU: $CPU_ID"
        echo 0 > "$CPU_PATH/online" 2>/dev/null || echo "[WARN] Failed to offline CPU $CPU_ID"
    elif [ "$ACTION" == "enable" ]; then
        echo "[INFO] Onlining hyperthreaded CPU: $CPU_ID"
        echo 1 > "$CPU_PATH/online" 2>/dev/null || echo "[WARN] Failed to online CPU $CPU_ID"
    fi
done

echo
echo "[INFO] Current CPU layout:"
lscpu | grep -i -E "^CPU\(s\):|core|socket|Thread"

echo
echo "[DONE] Hyperthreading $ACTION operation complete."