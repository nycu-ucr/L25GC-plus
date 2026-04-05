#!/bin/bash
# set -e

# Check arg
if [ -z "$1" ]; then
    echo "Usage: $0 <ue|cn|dn>"
    exit 1
fi

# Target
TARGET="$1"
SCRIPT_DIR=$(dirname "$0")
UE_LABEL="${2:-ueransim}"

UE_ARG=""
if [ "$TARGET" = "ue" ]; then
    case "$UE_LABEL" in
        ueransim)
            UE_ARG="--ueransim"
            ;;
        oai)
            UE_ARG="--oai"
            ;;
        -h|--help)
            echo "Usage: $0 <ue|cn|dn> [ueransim|oai]"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown ue label: $UE_LABEL"
            exit 1
            ;;
    esac
fi

# Run setup scripts
for script in "$SCRIPT_DIR"/*_setup_"${TARGET}"*.sh; do
    if [[ -f "$script" ]]; then
        echo "Running $script..."
        if [ "$TARGET" = "ue" ]; then
            bash "$script" "$UE_ARG"
        else
            bash "$script"
        fi
    else
        echo "No scripts provided."
    fi
done
