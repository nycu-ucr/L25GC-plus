#!/bin/bash

# Run Registration Test with Data Plane Testing
# This script runs the 3GPP registration test including ping validation

set -e

echo "========================================"
echo "Registration Test with Data Plane"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if MongoDB is running
echo "🔍 Checking MongoDB..."
if ! systemctl is-active --quiet mongod; then
    echo "⚠️  MongoDB is not running. Starting MongoDB..."
    systemctl start mongod
    sleep 3
fi

if systemctl is-active --quiet mongod; then
    echo "✅ MongoDB is running"
else
    echo "❌ Failed to start MongoDB"
    exit 1
fi

# Clean up old GRE tunnel if exists
echo ""
echo "🧹 Cleaning up old GRE tunnel..."
ip link del gretun 2>/dev/null || true
echo "✓ Cleanup complete"

# Change to test directory
cd "$(dirname "$0")"

echo ""
echo "========================================"
echo "Running Registration Test"
echo "========================================"
echo ""
echo "Test includes:"
echo "  ✅ NG Setup"
echo "  ✅ UE Registration (5G-AKA)"
echo "  ✅ PDU Session Establishment"
echo "  ✅ GRE Tunnel Setup"
echo "  ✅ Ping Test (60.60.0.1 → 60.60.0.101)"
echo ""
echo "Expected duration: 15-20 seconds"
echo ""

# Run test with proper environment and timeout
timeout 60 sudo -E env "PATH=$PATH:/usr/local/go/bin" \
    go test -v -timeout 60s \
    registration_test.go ranUe.go security.go mongodb.go packet.go decode.go gtp.go \
    -run TestRegistration

TEST_RESULT=$?

echo ""
echo "========================================"
echo "Test Result"
echo "========================================"
if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ Test PASSED!"
    echo ""
    echo "Test completed successfully:"
    echo "  ✅ Registration completed"
    echo "  ✅ PDU Session established"
    echo "  ✅ Data plane tested"
else
    echo "❌ Test FAILED or TIMED OUT (exit code: $TEST_RESULT)"
    echo ""
    echo "Common failure points:"
    echo "  - MongoDB slow to respond"
    echo "  - Core network components not running"
    echo "  - GRE tunnel creation failed"
    echo "  - UPF not configured for 60.60.0.0/24"
    echo ""
    echo "Debug commands:"
    echo "  ip link show gretun             # Check GRE tunnel"
    echo "  ip addr show gretun             # Check UE IP (60.60.0.1)"
    echo "  ip route | grep gretun          # Check routing"
    echo "  ps aux | grep upf               # Check UPF is running"
fi

# Cleanup
echo ""
echo "🧹 Cleaning up GRE tunnel..."
ip link del gretun 2>/dev/null || true

exit $TEST_RESULT

