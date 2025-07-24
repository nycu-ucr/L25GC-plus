#!/bin/bash
set -e

# Check arg
if [ -z "$1" ]; then
    echo "Usage: $0 <ue|cn|dn>"
    exit 1
fi

# Target
TARGET="$1"
SCRIPT_DIR=$(dirname "$0")

# Run setup scripts
for script in "$SCRIPT_DIR"/*_setup_"${TARGET}"*.sh; do
    if [[ -f "$script" ]]; then
        echo "Running $script..."
        bash "$script"
    else
        echo "No scripts provided."
    fi
done
