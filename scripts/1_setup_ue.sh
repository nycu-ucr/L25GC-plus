#!/usr/bin/bash

# ==============================================================================
# UE/RAN Node Setup Script
# Installs dependencies and builds UERANSIM for 5G User Equipment simulation
# ==============================================================================

# ----[ Constants ]------------------------------------------------------------
WORK_DIR=$HOME
CMAKE_VERSION="3.30.1"
CMAKE_SCRIPT="cmake-${CMAKE_VERSION}-linux-x86_64.sh"

# ----[ System Update and Package Installation ]-------------------------------
echo "[INFO] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[INFO] Installing required development and networking tools..."
sudo apt install make git iperf3 net-tools g++ libsctp-dev lksctp-tools iproute2 -y

# ----[ Install Specific Version of CMake ]------------------------------------
echo "[INFO] Downloading and installing CMake $CMAKE_VERSION..."

cd $WORK_DIR
wget https://github.com/Kitware/CMake/releases/download/v3.30.1/cmake-3.30.1-linux-x86_64.sh
chmod 744 cmake-3.30.1-linux-x86_64.sh

# Install CMake into /opt/cmake (or keep default if prompted)
sudo bash `pwd`/cmake-3.30.1-linux-x86_64.sh
# sudo bash "./$CMAKE_SCRIPT"

# Add symlinks to make cmake and friends available system-wide
sudo ln -s `pwd`/cmake-3.30.1-linux-x86_64/bin/* /usr/local/bin/
# sudo ln -sf "$WORK_DIR/cmake-${CMAKE_VERSION}-linux-x86_64/bin/"* /usr/local/bin/

# ----[ Build UERANSIM ]---------------------------------------------
echo "[INFO] Building UERANSIM..."
cd $WORK_DIR/L25GC-plus/UERANSIM
make -j

echo "[INFO] UERANSIM installation complete."