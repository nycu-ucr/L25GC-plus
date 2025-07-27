#!/bin/bash
set -e

# -----------------------------------------
# Start script for ONVM Manager
# -----------------------------------------

# Set working directory (default: user home directory)
WORK_DIR=$HOME
DEFAULT_ONVM_MGR_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf"

DEFAULT_CORE_ID="3"
DEFAULT_PORTMASK="0xFFF8"
DEFAULT_OUTPUT="stdout"

# Usage function
usage() {
  echo "Usage: $0 [-p ONVM_MGR_PATH] [-k CORE_ID] [-n PORTMASK] [-s OUTPUT]"
  echo
  echo "  -p ONVM_MGR_PATH   Path to ONVM-UPF (default: $DEFAULT_ONVM_MGR_PATH)"
  echo "  -k CORE_ID    Core ID to assign (default: $DEFAULT_CORE_ID)"
  echo "  -n PORTMASK   DPDK portmask (default: $DEFAULT_PORTMASK)"
  echo "  -s OUTPUT     Output mode (default: $DEFAULT_OUTPUT)"
  exit 1
}

# Parse input arguments
while getopts "p:k:n:s:h" opt; do
  case $opt in
    p) ONVM_MGR_PATH="$OPTARG" ;;
    k) CORE_ID="$OPTARG" ;;
    n) PORTMASK="$OPTARG" ;;
    s) OUTPUT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Apply defaults if not provided
ONVM_MGR_PATH="${ONVM_MGR_PATH:-$DEFAULT_ONVM_MGR_PATH}"
CORE_ID="${CORE_ID:-$DEFAULT_CORE_ID}"
PORTMASK="${PORTMASK:-$DEFAULT_PORTMASK}"
OUTPUT="${OUTPUT:-$DEFAULT_OUTPUT}"

# Check that the directory exists
if [ ! -d "$ONVM_MGR_PATH" ]; then
  echo "Error: ONVM MGR path does not exist: $ONVM_MGR_PATH"
  echo "Usage: $0 [ONVM_MGR_PATH]"
  exit 1
fi

echo "[INFO] Changing directory to: $ONVM_MGR_PATH"
cd "$ONVM_MGR_PATH"

# Small delay to ensure environment is ready
sleep 1.0

# Launch ONVM_MGR with specified arguments
echo "[INFO] Starting ONVM_MGR with options: -k $CORE_ID -n $PORTMASK -s $OUTPUT"
./scripts/start.sh -k "$CORE_ID" -n "$PORTMASK" -s "$OUTPUT"