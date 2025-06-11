#!/usr/bin/bash
### Constants
WORK_DIR=$HOME

### Install Packages
sudo apt update && sudo apt upgrade -y
# env setup
sudo apt install net-tools -y
# essential for build
sudo apt install libnuma-dev -y
# mongo
sudo apt install -y gnupg curl
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org 
sudo systemctl start mongod

### free5GC webconsole
cd $WORK_DIR
git clone --recursive -b v4.0.0 -j `nproc` https://github.com/free5gc/free5gc.git
cd free5gc
# install nodejs
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 
sudo apt update
sudo apt install -y nodejs
sudo corepack enable 
# make webconsole 
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin
make webconsole

### L25GC+
cd $WORK_DIR
git clone https://github.com/nycu-ucr/L25GC-plus.git
cd L25GC-plus
git clone https://github.com/nycu-ucr/onvmpoller.git

cd $HOME
git clone https://github.com/nycu-ucr/onvm.git

cd $HOME/onvm
git checkout opensource

git clone https://github.com/nycu-ucr/onvm-upf.git
cd onvm-upf
git submodule sync
git submodule update --init

### User Space
echo "alias dpdk-devbind='sudo $WORK_DIR/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py'" >> ~/.bashrc
sudo sysctl -w net.ipv4.ip_forward=1
sudo systemctl stop ufw
sudo systemctl disable ufw

# ./install.sh


