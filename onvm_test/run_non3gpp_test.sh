#!/bin/bash

# cd /users/will_lin/L25GC-plus/onvm_test

echo "========================================"
echo "Running Non-3GPP Test"
echo "========================================"
echo ""

# Check if N3IWF is running
if [ ! -f n3iwf_test.pid ]; then
    echo "❌ N3IWF is not running!"
    echo "Start it first: sudo ./start_n3iwf.sh"
    exit 1
fi

PID=$(cat n3iwf_test.pid)
if ! ps -p $PID > /dev/null 2>&1; then
    echo "❌ N3IWF is not running!"
    echo "Start it first: sudo ./start_n3iwf.sh"
    exit 1
fi

echo "✓ N3IWF is running (PID: $PID)"
echo ""

# Clean up old XFRM rules and interfaces (from previous test runs)
echo "Cleaning up old XFRM rules and interfaces..."
sudo ip xfrm policy flush 2>/dev/null
sudo ip xfrm state flush 2>/dev/null
# Delete old XFRM interfaces
sudo ip link del xfrmi-default 2>/dev/null || true
for iface in $(ip link show | grep "ipsec-test-" | cut -d: -f2 | cut -d@ -f1 | tr -d ' ' 2>/dev/null); do
    sudo ip link del "$iface" 2>/dev/null || true
done
echo "✓ XFRM rules and interfaces cleaned"
echo ""

# Set up Go environment
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

# Check MongoDB
if ! sudo systemctl is-active mongod > /dev/null 2>&1; then
    echo "⚠️  Warning: MongoDB might not be running"
fi

# Check AMF
if ! ps aux | grep -v grep | grep "bin/amf" > /dev/null; then
    echo "⚠️  Warning: AMF might not be running"
fi

echo "========================================"
echo "Starting Test (may take 10-30 seconds)"
echo "========================================"
echo ""

# Run the test (sudo -E to preserve environment, or use full path)
# Note: tools.go is excluded due to build constraints
sudo -E env "PATH=$PATH" "GOPATH=$GOPATH" "GOROOT=$GOROOT" go test -v -timeout 60s non3gpp_test.go ranUe.go security.go mongodb.go packet.go decode.go gtp.go -run TestNon3GPPUE

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "========================================"
    echo "✅ TEST PASSED!"
    echo "========================================"
else
    echo "========================================"
    echo "❌ TEST FAILED"
    echo "========================================"
    echo ""
    echo "Check N3IWF logs: tail -50 n3iwf_test.log"
    echo "Check test output above for errors"
fi
echo ""

exit $TEST_EXIT_CODE

