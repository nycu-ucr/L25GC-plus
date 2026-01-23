#!/bin/bash

# Start iperf3 Server for Data Plane Testing
# This script starts an iperf3 server bound to the DN IP

DN_IP="60.60.0.101"

echo "=========================================="
echo "Starting iperf3 Server"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if iperf3 is installed
if ! command -v iperf3 &> /dev/null; then
    echo "❌ iperf3 is not installed"
    echo "Install with: sudo apt-get install iperf3"
    exit 1
fi

# Check if DN IP is configured
if ! ip addr show | grep -q "$DN_IP"; then
    echo "⚠️  DN IP $DN_IP not configured"
    echo "Run: sudo ./setup_data_network.sh"
    exit 1
fi

# Check if iperf3 server is already running
if pgrep -f "iperf3.*-s.*$DN_IP" > /dev/null; then
    echo "✅ iperf3 server already running on $DN_IP"
    echo ""
    echo "To stop: sudo pkill -f 'iperf3.*-s'"
    exit 0
fi

echo "🚀 Starting iperf3 server on $DN_IP:5201..."
echo ""

# Start iperf3 server in background
nohup iperf3 -s -B $DN_IP > /tmp/iperf3_server.log 2>&1 &
IPERF_PID=$!

# Wait a moment and verify it started
sleep 1

if ps -p $IPERF_PID > /dev/null; then
    echo "✅ iperf3 server started successfully!"
    echo ""
    echo "Server details:"
    echo "  - IP: $DN_IP"
    echo "  - Port: 5201 (default)"
    echo "  - PID: $IPERF_PID"
    echo "  - Log: /tmp/iperf3_server.log"
    echo ""
    echo "Test connection:"
    echo "  iperf3 -c $DN_IP -t 3"
    echo ""
    echo "Stop server:"
    echo "  sudo pkill -f 'iperf3.*-s'"
    echo ""
else
    echo "❌ Failed to start iperf3 server"
    echo "Check log: cat /tmp/iperf3_server.log"
    exit 1
fi

exit 0
