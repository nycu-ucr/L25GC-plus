#!/bin/bash

# Complete Data Plane Test Setup and Execution
# This script sets up everything needed and runs the full test

set -e

echo "=========================================="
echo "L25GC-plus Full Data Plane Test"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Change to script directory
cd "$(dirname "$0")"

# Step 1: Setup Data Network
echo "Step 1/4: Setting up Data Network..."
echo "─────────────────────────────────"
./setup_data_network.sh
echo ""

# Step 2: Start iperf3 server
echo "Step 2/4: Starting iperf3 server..."
echo "─────────────────────────────────"
./start_iperf3_server.sh
echo ""

# Step 3: Wait for services to stabilize
echo "Step 3/4: Waiting for services to stabilize..."
echo "─────────────────────────────────"
sleep 2
echo "✅ Ready"
echo ""

# Step 4: Run the test
echo "Step 4/4: Running registration test..."
echo "─────────────────────────────────"
echo ""
./run_registration_test.sh

TEST_RESULT=$?

echo ""
echo "=========================================="
echo "Cleanup"
echo "=========================================="

# Stop iperf3 server
echo "🧹 Stopping iperf3 server..."
pkill -f 'iperf3.*-s' 2>/dev/null || true
echo "✅ Cleanup complete"

echo ""
echo "=========================================="
echo "Final Result"
echo "=========================================="
if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ FULL DATA PLANE TEST PASSED!"
    echo ""
    echo "Summary:"
    echo "  ✅ Control Plane: Working"
    echo "  ✅ Data Plane Ping: Working"
    echo "  ✅ Data Plane Throughput: Working"
else
    echo "❌ Test failed (exit code: $TEST_RESULT)"
fi

exit $TEST_RESULT
