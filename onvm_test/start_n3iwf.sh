#!/bin/bash

cd /users/will_lin/L25GC-plus/onvm_test

echo "========================================"
echo "Starting N3IWF for Non-3GPP Test"
echo "========================================"
echo ""

# Check if already running
if [ -f n3iwf_test.pid ]; then
    PID=$(cat n3iwf_test.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo "⚠️  N3IWF is already running (PID: $PID)"
        echo ""
        echo "To stop it: sudo kill $PID"
        echo "To restart: sudo ./stop_n3iwf.sh && sudo ./start_n3iwf.sh"
        exit 0
    fi
fi

# Setup network interface
echo "[1/4] Setting up network interface..."
sudo ip link add name n3iwf-ue type dummy 2>/dev/null || true
sudo ip addr add 192.168.127.2/24 dev n3iwf-ue 2>/dev/null || true
sudo ip addr add 192.168.127.1/24 dev n3iwf-ue 2>/dev/null || true
sudo ip link set n3iwf-ue up
echo "✓ Network interface ready"

# Clean up any existing XFRM interface (from previous runs)
echo "[2/5] Cleaning up old XFRM interface..."
sudo ip link del xfrmi-default 2>/dev/null || true
sudo ip xfrm policy flush 2>/dev/null || true
sudo ip xfrm state flush 2>/dev/null || true

# Load kernel modules
echo "[3/5] Loading kernel modules..."
sudo modprobe af_key esp4 xfrm_user ip_gre 2>/dev/null || true
echo "✓ Kernel modules loaded"

# Check config exists
if [ ! -f config/n3iwfcfg_test.yaml ]; then
    echo "✗ Config file not found: config/n3iwfcfg_test.yaml"
    exit 1
fi

# Check n3iwf binary exists
if [ ! -f ../free5gc/NFs/n3iwf/n3iwf ]; then
    echo "✗ N3IWF binary not found"
    echo "Build it with: cd ../free5gc/NFs/n3iwf && go build -o n3iwf cmd/main.go"
    exit 1
fi

# Start N3IWF
echo "[4/5] Starting N3IWF..."
sudo nohup ../free5gc/NFs/n3iwf/n3iwf -c config/n3iwfcfg_test.yaml > n3iwf_test.log 2>&1 &
echo $! > n3iwf_test.pid
sleep 3

# Verify it started
PID=$(cat n3iwf_test.pid)
if ps -p $PID > /dev/null 2>&1; then
    echo "✓ N3IWF started (PID: $PID)"
else
    echo "✗ N3IWF failed to start"
    echo "Check log: tail -50 n3iwf_test.log"
    exit 1
fi

# Show status
echo "[5/5] Checking status..."
if grep -q "N3IWF started" n3iwf_test.log; then
    echo "✓ N3IWF is running successfully!"
else
    echo "⚠️  N3IWF may have issues, check log"
fi

echo ""
echo "========================================"
echo "✅ N3IWF Ready for Testing!"
echo "========================================"
echo ""
echo "To view logs:  tail -f n3iwf_test.log"
echo "To stop:       sudo ./stop_n3iwf.sh"
echo "To run test:   sudo ./run_non3gpp_test.sh"
echo ""
echo "========================================"
echo ""
echo "To view logs:  tail -f n3iwf_test.log"
echo "To stop:       sudo ./stop_n3iwf.sh"
echo "To run test:   sudo ./run_non3gpp_test.sh"
echo ""