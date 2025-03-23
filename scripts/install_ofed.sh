#!/bin/bash

# Description: install the ofed RDMA driver on cloublab machines with ubuntu20.04

# Sample input data
devices=$(lspci | grep "Mellanox")

echo "The devices found:"
echo "$devices"
echo ""

# Get the first line of input data
first_line=$(echo "$devices" | head -n 1)


# Extract the ConnectX version from the first line
version=$(echo "$first_line" | grep -o 'ConnectX-[0-9]*' | sed 's/ConnectX-//')

# Print the result
echo "Extracted version from the first line: $version"
echo ""
echo "=================="
echo "This script will install ofed driver for ubuntu20.04 on x86_64 machiens"
echo "Use this script at your own risk!!"
echo "=================="

echo "For other system and platforms, refer to https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/"

input=n
if [[ "$version" == "3" ]]; then
    read -p "The device is ConnectX-$version, will install ofed driver 4.9 (y/n)" input
    if [[ "$input" != "y" ]]; then
        exit 1
    fi
    cd $HOME
    wget https://content.mellanox.com/ofed/MLNX_OFED-4.9-7.1.0.0/MLNX_OFED_LINUX-4.9-7.1.0.0-ubuntu20.04-x86_64.tgz
    tar -xvf MLNX_OFED_LINUX-4.9-7.1.0.0-ubuntu20.04-x86_64.tgz
    cd MLNX_OFED_LINUX-4.9-7.1.0.0-ubuntu20.04-x86_64/
    sudo ./mlnxofedinstall --add-kernel-support
    exit 0
    echo "reboot the machine after sucessfule installation, failed to update firmware is OK"

fi

read -p "The device is ConnectX-$version, will install ofed driver 24.10 (y/n) " input
if [[ "$input" != "y" ]]; then
    exit 1
fi


echo "install ofed 24.10"
cd $HOME
wget -O ofed.tgz https://content.mellanox.com/ofed/MLNX_OFED-24.10-2.1.8.0/MLNX_OFED_LINUX-24.10-2.1.8.0-ubuntu20.04-x86_64.tgz
tar xvf ofed.tgz
cd MLNX_OFED_LINUX-24.10-2.1.8.0-ubuntu20.04-x86_64
sudo ./mlnxofedinstall --dpdk

echo "load new driver"
sudo /etc/init.d/openibd restart

echo "Install ofed driver finished, failed to update firmware is OK"
