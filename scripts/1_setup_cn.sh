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
UBUNTU_CODENAME="$(lsb_release -sc)"

# Decide MongoDB major by Ubuntu release
case "$UBUNTU_CODENAME" in
  focal|jammy) MONGO_MAJOR="7.0" ;;
  noble)       MONGO_MAJOR="8.0" ;;
  *)
    echo "[ERROR] Unsupported Ubuntu release: $UBUNTU_CODENAME"
    echo "Supported: 20.04 (focal), 22.04 (jammy), 24.04 (noble)"
    exit 1
    ;;
esac

KEYRING="/usr/share/keyrings/mongodb-server-${MONGO_MAJOR}.gpg"
LIST="/etc/apt/sources.list.d/mongodb-org-${MONGO_MAJOR}.list"

echo "[INFO] Adding MongoDB ${MONGO_MAJOR} APT repository for ${UBUNTU_CODENAME}..."
# Clean up any previous MongoDB repo entries to avoid APT errors
sudo rm -f /etc/apt/sources.list.d/mongodb-org-*.list || true

# Import the correct PGP key for this major version
curl -fsSL "https://www.mongodb.org/static/pgp/server-${MONGO_MAJOR}.asc" \
  | sudo gpg -o "${KEYRING}" --dearmor

# Add the apt source for this Ubuntu release and MongoDB major
echo "deb [ arch=amd64,arm64 signed-by=${KEYRING} ] https://repo.mongodb.org/apt/ubuntu ${UBUNTU_CODENAME}/mongodb-org/${MONGO_MAJOR} multiverse" \
  | sudo tee "${LIST}" > /dev/null

echo "[INFO] Updating package index..."
sudo apt-get update -y

echo "[INFO] Installing MongoDB ${MONGO_MAJOR}..."
sudo apt-get install -y mongodb-org

echo "[INFO] Enabling and starting MongoDB service..."
sudo systemctl enable mongod
sudo systemctl start mongod

# ------------------------------------------------------------------------------
# Build WebConsole (from free5GC)
# ------------------------------------------------------------------------------

echo "[INFO] Installing Node.js 20.x for WebConsole..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 
sudo apt install -y nodejs
sudo corepack enable 

echo "[INFO] Setting Go environment variables..."
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

echo "[INFO] Building WebConsole..."
cd $WORK_DIR/L25GC-plus/webconsole
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