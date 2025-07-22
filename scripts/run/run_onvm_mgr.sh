#!/bin/bash
set -e

# -----------------------------------------
# Start script for ONVM Manager
# -----------------------------------------

# Set working directory (default: user home directory)
WORK_DIR=$HOME
DEFAULT_UPF_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf"

DEFAULT_CORE_ID="3"
DEFAULT_PORTMASK="0xFFF8"
DEFAULT_OUTPUT="stdout"

# Usage function
usage() {
  echo "Usage: $0 [-p UPF_PATH] [-k CORE_ID] [-n PORTMASK] [-s OUTPUT]"
  echo
  echo "  -p UPF_PATH   Path to ONVM-UPF (default: $DEFAULT_UPF_PATH)"
  echo "  -k CORE_ID    Core ID to assign (default: $DEFAULT_CORE_ID)"
  echo "  -n PORTMASK   DPDK portmask (default: $DEFAULT_PORTMASK)"
  echo "  -s OUTPUT     Output mode (default: $DEFAULT_OUTPUT)"
  exit 1
}

# Parse input arguments
while getopts "p:k:n:s:h" opt; do
  case $opt in
    p) UPF_PATH="$OPTARG" ;;
    k) CORE_ID="$OPTARG" ;;
    n) PORTMASK="$OPTARG" ;;
    s) OUTPUT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Apply defaults if not provided
UPF_PATH="${UPF_PATH:-$DEFAULT_UPF_PATH}"
CORE_ID="${CORE_ID:-$DEFAULT_CORE_ID}"
PORTMASK="${PORTMASK:-$DEFAULT_PORTMASK}"
OUTPUT="${OUTPUT:-$DEFAULT_OUTPUT}"

# Check that the directory exists
if [ ! -d "$UPF_PATH" ]; then
  echo "Error: UPF path does not exist: $UPF_PATH"
  echo "Usage: $0 [UPF_PATH]"
  exit 1
fi

echo "[INFO] Changing directory to: $UPF_PATH"
cd "$UPF_PATH"

# Small delay to ensure environment is ready
sleep 1.0

# Launch UPF with specified arguments
echo "[INFO] Starting ONVM-UPF with options: -k $CORE_ID -n $PORTMASK -s $OUTPUT"
./scripts/start.sh -k "$CORE_ID" -n "$PORTMASK" -s "$OUTPUT"