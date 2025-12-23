#!/bin/bash

# Setup Data Network for L25GC-plus Testing
# This script configures the DN (Data Network) to respond to UE traffic

set -e

echo "=========================================="
echo "Setting Up Data Network (DN)"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

DN_IP="60.60.0.101"
DN_SUBNET="60.60.0.0/24"
DN_INTERFACE="lo"  # Using loopback for testing

echo "📡 Data Network Configuration:"
echo "  - DN IP: $DN_IP/24"
echo "  - Subnet: $DN_SUBNET"
echo "  - Interface: $DN_INTERFACE"
echo ""

# Add DN IP address to loopback interface
echo "🔧 Adding DN IP to $DN_INTERFACE..."
if ip addr show $DN_INTERFACE | grep -q "$DN_IP"; then
    echo "✅ DN IP $DN_IP already configured"
else
    ip addr add $DN_IP/24 dev $DN_INTERFACE
    echo "✅ Added DN IP: $DN_IP/24"
fi

# Verify IP is configured
echo ""
echo "🔍 Verifying configuration..."
if ip addr show $DN_INTERFACE | grep -q "$DN_IP"; then
    echo "✅ DN IP $DN_IP is active"
    ip addr show $DN_INTERFACE | grep "$DN_IP"
else
    echo "❌ Failed to configure DN IP"
    exit 1
fi

echo ""
echo "=========================================="
echo "✅ Data Network Setup Complete!"
echo "=========================================="
echo ""
echo "The DN is now ready at: $DN_IP"
echo ""
echo "Next steps:"
echo "  1. Start iperf3 server: sudo iperf3 -s -B $DN_IP &"
echo "  2. Run test: sudo ./run_registration_test.sh"
echo ""

exit 0
