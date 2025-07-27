#!/usr/bin/bash

# ==============================================================================
# Data Network (DN) Node Setup Script
# Installs required tools for DN traffic generation and diagnostics
# ==============================================================================

echo "[INFO] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[INFO] Installing iperf3 for traffic generation..."
echo "[INFO] Installing net-tools for network utilities (e.g., ifconfig, netstat)..."
sudo apt install iperf3 net-tools -y

echo "[INFO] DN setup complete."