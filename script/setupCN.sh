#!/bin/bash -i

# set up ip route
cd $HOME
sudo ip route del 192.168.1.0/24 dev enp6s0f1
sudo ip route add 192.168.1.4/32 dev enp6s0f1

# mongodb
cd $HOME
sudo apt install -y gnupg curl
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update
sudo apt install -y mongodb-org

cd $HOME/L25GC-plus
./install.sh



#webconsole
cd $HOME
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 
sudo apt update
sudo apt install -y nodejs
sudo corepack enable # setup yarn automatically
cd $HOME
git clone --recursive -b v3.3.0 -j `nproc` https://github.com/free5gc/free5gc.git
cd free5gc
source ~/.bashrc
make webconsole