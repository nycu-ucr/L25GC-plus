#!/bin/bash
set -e

# -----------------------------------------
# Start script for ONVM Manager
# -----------------------------------------

# Set working directory (default: user home directory)
WORK_DIR=$HOME
DEFAULT_ONVM_MGR_PATH="$WORK_DIR/L25GC-plus/NFs/onvm-upf"


# Defaults:
# - Manager cores (in start.sh) default to 0,1,2 if -m is not passed
# - Here we only set:
#     -k PORTMASK     (which NIC ports)
#     -n NF_COREMASK  (which cores ONVM can use for NFs)
DEFAULT_PORTMASK="3"
DEFAULT_NF_COREMASK="0xFFF8"
DEFAULT_OUTPUT="stdout"

# Usage function
usage() {
  echo "Usage: $0 [-p ONVM_MGR_PATH] [-k PORTMASK] [-n NF_COREMASK] [-s OUTPUT]"
  echo
  echo "  -p ONVM_MGR_PATH   Path to ONVM-UPF (default: $DEFAULT_ONVM_MGR_PATH)"
  echo "  -k PORTMASK        DPDK portmask passed to start.sh -k (default: $DEFAULT_PORTMASK)"
  echo "                     Example: 3 -> use ports 0 and 1"
  echo "  -n NF_COREMASK     NF coremask passed to start.sh -n (default: $DEFAULT_NF_COREMASK)"
  echo "                     Example: 0xF0 -> cores 4-7 for NFs"
  echo "  -s OUTPUT          Stats/output mode (web|stdout) (default: $DEFAULT_OUTPUT)"
  exit 1
}

# Parse input arguments
while getopts "p:k:n:s:h" opt; do
  case $opt in
    p) ONVM_MGR_PATH="$OPTARG" ;;
    k) PORTMASK="$OPTARG" ;;
    n) NF_COREMASK="$OPTARG" ;;
    s) OUTPUT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Apply defaults if not provided
ONVM_MGR_PATH="${ONVM_MGR_PATH:-$DEFAULT_ONVM_MGR_PATH}"
PORTMASK="${PORTMASK:-$DEFAULT_PORTMASK}"
NF_COREMASK="${NF_COREMASK:-$DEFAULT_NF_COREMASK}"
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
echo "[INFO] Starting ONVM_MGR with options: -k $PORTMASK -n $NF_COREMASK -s $OUTPUT"
./scripts/start.sh -k "$PORTMASK" -n "$NF_COREMASK" -s "$OUTPUT"