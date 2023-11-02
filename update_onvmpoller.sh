#!/bin/bash
YELLOW='\033[1;33m'
NC='\033[0m'

workdir=$(pwd)
github_dir="$HOME/go/pkg/mod/github.com/nycu-ucr"

cd $github_dir

echo -e "Replace ${YELLOW}/home/johnson${NC} to ${YELLOW}$HOME${NC}"
echo -e "Put onvm directory under your $HOME"
# onvmpoller
for target in $(ls | grep 'onvmpoller@*')
do
    cd $github_dir
    echo "Handle $target"
    sudo cp -R $workdir/onvmpoller/* $target
    cd $target
    sudo sed -i "s#/home/hstsai#$HOME#g" poller.go
    sudo sed -i "s#/home/hstsai#$HOME#g" onvm_poller.c
    sudo sed -i "s#/home/johnson#$HOME#g" poller.go
    sudo sed -i "s#/home/johnson#$HOME#g" onvm_poller.c
    sudo rm -f listen.go
done
