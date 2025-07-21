#!/bin/bash -i
set -e

# ==============================================================================
# L25GC+ Control Plane and User Plane Setup Script
# ==============================================================================

# ------------------------------------------------------------------------------
# Color Constants for Logging
# ------------------------------------------------------------------------------

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# Update and Install Basic Packages
# ------------------------------------------------------------------------------

cd $HOME
sudo apt -y install cmake autoconf libtool pkg-config libmnl-dev

# ------------------------------------------------------------------------------
# Clone and Initialize Control Plane NFs
# ------------------------------------------------------------------------------

echo "[INFO] Cloning L25GC+ and dependencies..."
cd $HOME/L25GC-plus
git submodule sync
git submodule update --init

# ------------------------------------------------------------------------------
# Clone and Build ONVM
# ------------------------------------------------------------------------------

cd $HOME/L25GC-plus/NFs/onvm-upf
# git checkout opensource
git checkout tmp-merge

git submodule sync
git submodule update --init

echo -e "${YELLOW}Build and install DPDK, go1.21, igb_uio${NC}"
./scripts/install.sh
./scripts/setup_runtime.sh

# Source .bashrc to make Go env active
source ~/.bashrc

# Building ONVM, UPF-U, and UPF-C
./scripts/build.sh

# ------------------------------------------------------------------------------
# Setup Environment Variables
# ------------------------------------------------------------------------------

cd $HOME/L25GC-plus
sudo rm -rf $HOME/.cache

echo "export ONVMPOLLER_IPID_YAML=$HOME/L25GC-plus/onvm_nf_configs/ipid.yaml" >> ~/.bashrc
echo "export ONVMPOLLER_NFIP_YAML=$HOME/L25GC-plus/onvm_nf_configs/NFip.yaml" >> ~/.bashrc
echo "export ONVMPOLLER_IPID_TXT=$HOME/L25GC-plus/onvm_nf_configs/ipid.txt" >> ~/.bashrc
echo "export CGO_LDFLAGS_ALLOW='-Wl,(--whole-archive|--no-whole-archive)'" >> ~/.bashrc
echo "export ONVM_NF_JSON=$HOME/L25GC-plus/onvm_nf_configs/" >> ~/.bashrc
source ~/.bashrc

# ------------------------------------------------------------------------------
# Build Control Plane NFs and Link X-IO
# ------------------------------------------------------------------------------

# 5GC NFs to Compile
NFs="nrf amf smf udr pcf udm nssf ausf chf"
for nf in $NFs
do
    ./scripts/update_xio.sh
    rm -rf $HOME/.cache
    make $nf
done
# done

# ------------------------------------------------------------------------------
# Final Onvmpoller Update and Cleanup
# ------------------------------------------------------------------------------

cd $HOME/L25GC-plus
./scripts/update_xio.sh
sudo rm -rf ~/.cache

# Optional cleanup (commented out)
# cd $HOME/L25GC-plus/onvm_test
# sudo rm -rf ~/go/pkg/mod/github.com
# sudo rm -rf ~/go/pkg/mod/cache
# go mod tidy

source ~/.bashrc

echo -e "${GREEN}Setup complete!${NC}"