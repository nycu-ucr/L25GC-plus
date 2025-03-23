#!/usr/bin/bash
# Constant
WORK_DIR=$HOME

# Install pkgs
sudo apt update && sudo apt upgrade -y
sudo apt install make git iperf3 net-tools
sudo apt install -y make git g++ libsctp-dev lksctp-tools iproute2

# Install cmake
cd $WORK_DIR
wget https://github.com/Kitware/CMake/releases/download/v3.30.1/cmake-3.30.1-linux-x86_64.sh
chmod 744 cmake-3.30.1-linux-x86_64.sh
sudo bash `pwd`/cmake-3.30.1-linux-x86_64.sh
sudo ln -s `pwd`/cmake-3.30.1-linux-x86_64/bin/* /usr/local/bin/

# UERANSIM
cd $WORK_DIR
git clone https://github.com/aligungr/UERANSIM.git
cd UERANSIM
make
