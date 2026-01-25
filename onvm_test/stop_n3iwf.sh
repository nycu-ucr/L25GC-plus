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
        echo "[1/4] Stopping N3IWF (PID: $PID)..."
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
fi

# Kill any remaining N3IWF processes (comprehensive cleanup)
echo "[2/4] Killing any remaining N3IWF processes..."
sudo pkill -9 -f "n3iwf.*n3iwfcfg_test.yaml" 2>/dev/null || true
sudo pkill -9 -f "n3iwf.*config/n3iwfcfg_test" 2>/dev/null || true
sudo pkill -9 n3iwf 2>/dev/null || true
sleep 1

# Check if port 20000 is still in use and kill the process
if sudo lsof -ti :20000 > /dev/null 2>&1; then
    echo "⚠️  Port 20000 still in use, killing process..."
    sudo kill -9 $(sudo lsof -ti :20000) 2>/dev/null || true
    sleep 1
fi
echo "✓ All N3IWF processes cleaned"

# Clean up network interface
echo "[3/4] Cleaning up network interface..."
sudo ip link del n3iwf-ue 2>/dev/null || true
echo "✓ Network interface removed"

# Clean up XFRM interface and policies
echo "[4/4] Cleaning up XFRM interface and policies..."
# Force down and delete xfrmi-default (critical for restart!)
sudo ip link set xfrmi-default down 2>/dev/null || true
sleep 0.5
sudo ip link del xfrmi-default 2>/dev/null || true
sleep 0.5
# Verify it's gone
if ip link show xfrmi-default > /dev/null 2>&1; then
    echo "⚠️  Warning: xfrmi-default still exists, forcing deletion..."
    sudo ip link del xfrmi-default 2>/dev/null || true
fi
sudo ip xfrm policy flush 2>/dev/null || true
sudo ip xfrm state flush 2>/dev/null || true
echo "✓ XFRM interface and policies cleaned"

echo ""
echo "========================================"
echo "✅ N3IWF Stopped!"
echo "========================================"
echo ""


