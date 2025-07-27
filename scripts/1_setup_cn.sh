#!/usr/bin/bash
# set -e

# ==============================================================================
# L25GC+ and WebConsole Setup Script
# ==============================================================================

# Set working directory (default: user home directory)
WORK_DIR=$HOME

# ------------------------------------------------------------------------------
# Update and install basic packages
# ------------------------------------------------------------------------------

echo "[INFO] Updating system packages..."
sudo apt update

echo "[INFO] Installing essential utilities..."
sudo apt install -y net-tools gnupg curl

# ------------------------------------------------------------------------------
# Clone and install L25GC+ NFs
# ------------------------------------------------------------------------------

echo "[INFO] Running L25GC+ install script..."
cd $WORK_DIR/L25GC-plus
./scripts/install_nfs.sh 

# ------------------------------------------------------------------------------
# Install MongoDB (required for WebConsole)
# ------------------------------------------------------------------------------

echo "[INFO] Detecting Ubuntu codename..."
UBUNTU_CODENAME=$(lsb_release -sc)

# Validate supported versions
if [[ "$UBUNTU_CODENAME" != "focal" && "$UBUNTU_CODENAME" != "jammy" && "$UBUNTU_CODENAME" != "noble" ]]; then
    echo "[ERROR] Unsupported Ubuntu release: $UBUNTU_CODENAME"
    echo "Supported versions: 20.04 (focal), 22.04 (jammy), 24.04 (noble)"
    exit 1
fi

echo "[INFO] Adding MongoDB 7.0 APT repository for $UBUNTU_CODENAME..."
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
    sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu $UBUNTU_CODENAME/mongodb-org/7.0 multiverse" | \
sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list > /dev/null

echo "[INFO] Updating package index..."
sudo apt update

echo "[INFO] Installing MongoDB 7.0..."
sudo apt install -y mongodb-org

echo "[INFO] Enabling and starting MongoDB service..."
sudo systemctl enable mongod
sudo systemctl start mongod

# ------------------------------------------------------------------------------
# Clone and build WebConsole (from free5GC)
# ------------------------------------------------------------------------------

echo "[INFO] Cloning free5GC repository with webconsole..."
cd $WORK_DIR
git clone --recursive -b v4.0.0 -j `nproc` https://github.com/free5gc/free5gc.git

echo "[INFO] Installing Node.js 20.x for WebConsole..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 
sudo apt install -y nodejs
sudo corepack enable 

echo "[INFO] Setting Go environment variables..."
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

echo "[INFO] Building WebConsole..."
cd free5gc
make webconsole

# ------------------------------------------------------------------------------
# Miscellaneous
# ------------------------------------------------------------------------------

echo "[INFO] Adding DPDK devbind alias to .bashrc..."
echo "alias dpdk-devbind='sudo $HOME/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py'" >> ~/.bashrc

echo "[INFO] Enabling IP forwarding and disabling firewall..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo systemctl stop ufw
sudo systemctl disable ufw

echo "[INFO] Setup complete."