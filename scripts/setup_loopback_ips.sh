#!/bin/bash

echo "========================================"
echo "Setting up Loopback IPs for L25GC+"
echo "========================================"

# Core Network IPs on loopback interface
# These IPs are required for NFs to communicate via SBI and N2 interfaces
REQUIRED_IPS=(
    "127.0.0.2/8"   # N3IWF
    "127.0.0.3/8"   # UDM (CRITICAL for Non-3GPP test - AMF needs UDM for registration)
    "127.0.0.4/8"   # UDR
    "127.0.0.10/8"  # NRF
    "127.0.0.18/8"  # AMF (CRITICAL for Non-3GPP test - N3IWF connects here via SCTP)
    "127.0.0.20/8"  # AUSF
    "127.0.0.33/8"  # UPF (GTP-U)
)

for ip in "${REQUIRED_IPS[@]}"; do
    echo -n "Adding $ip to loopback... "
    if sudo ip addr add $ip dev lo 2>/dev/null; then
        echo "✓ Added"
    else
        if ip addr show lo | grep -q "${ip%%/*}"; then
            echo "✓ Already exists"
        else
            echo "✗ Failed"
        fi
    fi
done

echo ""
echo "Current loopback IPs:"
ip addr show lo | grep "inet " | awk '{print "  " $2}'

echo ""
echo "========================================"
echo "✓ Loopback IP setup complete"
echo "========================================"

echo "========================================"
echo "✓ Loopback IP setup complete"
echo "========================================"
