#!/bin/bash -i

# install UERANSIM
cd $HOME
git clone https://github.com/aligungr/UERANSIM
cd UERANSIM
# if using free5GC v3.3.0 or below
git checkout 3a96298

cd $HOME
sudo apt update
sudo apt upgrade
sudo apt install libsctp-dev

# install cmake
wget https://github.com/Kitware/CMake/releases/download/v3.17.0/cmake-3.17.0.tar.gz
tar -zxvf cmake-3.17.0.tar.gz
cd $HOME/cmake-3.17.0
./bootstrap
make
sudo make install

# make UERANSIM
cd $HOME/UERANSIM
make

git commit -m "add environment setup script and edit README.md