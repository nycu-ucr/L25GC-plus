#!/bin/bash

cd /users/will_lin/L25GC-plus/onvm_test

echo "========================================"
echo "Stopping N3IWF for Non-3GPP Test"
echo "========================================"
echo ""

# Kill N3IWF process
if [ -f n3iwf_test.pid ]; then
    PID=$(cat n3iwf_test.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo "[1/3] Stopping N3IWF (PID: $PID)..."
        sudo kill $PID 2>/dev/null
        sleep 2
        # Force kill if still running
        if ps -p $PID > /dev/null 2>&1; then
            sudo kill -9 $PID 2>/dev/null
            sleep 1
        fi
        echo "✓ N3IWF stopped"
    else
        echo "⚠️  N3IWF process not found (PID: $PID)"
    fi
    rm -f n3iwf_test.pid
else
    echo "⚠️  PID file not found, trying to kill by name..."
    sudo pkill -f "n3iwf.*n3iwfcfg_test.yaml" 2>/dev/null || true
    sleep 1
fi

# Clean up network interface
echo "[2/3] Cleaning up network interface..."
sudo ip link del n3iwf-ue 2>/dev/null || true
echo "✓ Network interface removed"

# Clean up XFRM interface and policies
echo "[3/3] Cleaning up XFRM interface and policies..."
sudo ip link del xfrmi-default 2>/dev/null || true
sudo ip xfrm policy flush 2>/dev/null || true
sudo ip xfrm state flush 2>/dev/null || true
echo "✓ XFRM interface and policies cleaned"

echo ""
echo "========================================"
echo "✅ N3IWF Stopped!"
echo "========================================"
echo ""


