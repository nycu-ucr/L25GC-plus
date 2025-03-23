#!/usr/bin/bash
### Constants
WORK_DIR=$HOME

### Install Packages
sudo apt update && sudo apt upgrade -y
# essential for build
sudo apt install libnuma-dev
# mongo
sudo apt install -y gnupg curl
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/7.0 multiverse" | \
sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org 
sudo systemctl start mongod

### L25GC
cd $WORK_DIR
git clone https://github.com/nycu-ucr/L25GC-plus.git
cd L25GC-plus
git clone https://github.com/nycu-ucr/onvmpoller.git
./install.sh 

### free5GC webconsole
cd $WORK_DIR
git clone --recursive -b v3.3.0 -j `nproc` https://github.com/free5gc/free5gc.git
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

### User Space
echo "alias dpdk-devbind='sudo $WORK_DIR/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py'" >> ~/.bashrc
sudo sysctl -w net.ipv4.ip_forward=1
sudo systemctl stop ufw
sudo systemctl disable ufw
