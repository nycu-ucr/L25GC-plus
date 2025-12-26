#!/bin/bash

# Run Non-3GPP Test with proper timeout and environment
# This script ensures MongoDB is ready and runs the test with sufficient timeout

set -e

echo "======================================"
echo "Non-3GPP Test Runner"
echo "======================================"
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

# Check if N3IWF is running
echo ""
echo "🔍 Checking N3IWF..."
if pgrep -x "n3iwf" > /dev/null; then
    echo "✅ N3IWF is running"
else
    echo "❌ N3IWF is not running!"
    echo "   Please start N3IWF first:"
    echo "   cd /path/to/n3iwf && sudo ./n3iwf"
    exit 1
fi

# Check if AMF is running
echo ""
echo "🔍 Checking AMF..."
if pgrep -x "amf" > /dev/null; then
    echo "✅ AMF is running"
else
    echo "⚠️  AMF is not running (may cause test to fail)"
fi

# Clean up old XFRM policies and states from previous failed tests
echo ""
echo "🧹 Cleaning up old XFRM policies/states from previous tests..."
# Note: This will NOT delete N3IWF's policies because they use specific SPIs
# Only clean up stale policies with old UE IPs (10.0.0.2-10.0.0.254)
echo "   (Skipping cleanup to preserve N3IWF's policies)"
# ip xfrm policy flush || true
# ip xfrm state flush || true

# Clean up old TCP connections
echo ""
echo "🧹 Cleaning up old TCP connections..."
OLD_CONNS=$(ss -tan | grep -c "10.0.0.*:20000" || true)
if [ "$OLD_CONNS" -gt 0 ]; then
    echo "   Found $OLD_CONNS old connections (they will timeout naturally)"
fi

# Change to test directory
cd "$(dirname "$0")"

echo ""
echo "======================================"
echo "Running Non-3GPP Test"
echo "======================================"
echo ""
echo "Test timeout: 120s (with 180s shell timeout as safety)"
echo "Expected duration: 30-60s if all core components respond quickly"
echo ""

# Run test with proper environment and timeout
# - Keep environment variables (sudo -E)
# - Set GO test timeout to 120s
# - Set shell timeout to 180s (as safety net)
# - Preserve PATH with Go binary location

timeout 180 sudo -E env "PATH=$PATH:/usr/local/go/bin" \
    go test -v -timeout 120s \
    non3gpp_test.go ranUe.go security.go mongodb.go packet.go decode.go gtp.go \
    -run TestNon3GPPUE

TEST_RESULT=$?

echo ""
echo "======================================"
echo "Test Result"
echo "======================================"
if [ $TEST_RESULT -eq 0 ]; then
    echo "✅ Test PASSED!"
    echo ""
    echo "Expected test flow completed:"
    echo "  1. IKE_SA_INIT"
    echo "  2. IKE_AUTH with EAP-5G"
    echo "  3. Registration (Auth Request/Response, Security Mode, EAP Success)"
    echo "  4. NAS TCP connection to N3IWF"
    echo "  5. Registration Complete sent"
    echo "  6. PDU Session Establishment"
    echo "  7. CREATE_CHILD_SA for user plane"
    echo "  8. GRE tunnel setup"
    echo "  9. Ping test (60.60.0.1 → 60.60.0.101)"
else
    echo "❌ Test FAILED or TIMED OUT (exit code: $TEST_RESULT)"
    echo ""
    echo "Common failure points:"
    echo "  - MongoDB slow to respond (restart MongoDB: sudo systemctl restart mongod)"
    echo "  - UDM not running (check: ps aux | grep udm)"
    echo "  - N3IWF not processing IKE messages (check N3IWF logs)"
    echo "  - AMF timeout on UDM queries (check AMF logs)"
    echo "  - TCP data stuck (check: sudo ss -tan | grep 20000)"
    echo ""
    echo "Debug commands:"
    echo "  sudo ss -tan | grep 20000              # Check TCP connections"
    echo "  sudo ip xfrm policy show               # Check XFRM policies"
    echo "  sudo ip addr show xfrmi-default        # Check UE IP on interface"
    echo "  tail -50 /path/to/n3iwf.log            # Check N3IWF logs"
    echo "  tail -50 /path/to/amf.log | grep -i nas   # Check AMF NAS processing"
fi

exit $TEST_RESULT






