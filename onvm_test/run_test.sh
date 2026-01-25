#!/bin/bash
# Helper script to run L25GC+ tests with custom network configuration
#
# Usage:
#   ./run_test.sh [test_name] [amf_ip] [ran_n2_ip] [ran_n3_ip] [ran_teid]
#
# Examples:
#   ./run_test.sh TestRegistration                              # Use defaults
#   ./run_test.sh TestRegistration 127.0.0.18 127.0.0.1         # Custom AMF and RAN N2 IPs
#   ./run_test.sh TestN2Handover 192.168.1.100 192.168.1.50 10.10.1.50 1
#

# Set defaults
TEST_NAME="${1:-TestRegistration}"
AMF_N2_IP="${2:-127.0.0.18}"
RAN_N2_IP="${3:-127.0.0.1}"
RAN_N3_IP="${4:-10.100.200.1}"
RAN_TEID="${5:-1}"

# Export environment variables
export AMF_N2_IP
export RAN_N2_IP
export RAN_N3_IP
export RAN_TEID

echo "========================================"
echo "Running $TEST_NAME with configuration:"
echo "  AMF_N2_IP: $AMF_N2_IP"
echo "  RAN_N2_IP: $RAN_N2_IP"
echo "  RAN_N3_IP: $RAN_N3_IP"
echo "  RAN_TEID:  $RAN_TEID"
echo "========================================"
echo ""

# Run the test
go test -v handover_test.go registration_test.go -run "$TEST_NAME"

