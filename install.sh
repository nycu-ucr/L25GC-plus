#!/bin/bash

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

NFs="nrf amf smf udr pcf udm nssf ausf"

cd $HOME
git clone https://github.com/nycu-ucr/onvm.git

cd $HOME/onvm
git checkout opensource

echo -e "${YELLOW}Install go1.19${NC}"
./install_go.sh

source ~/.bashrc
echo -e "${YELLOW}Build ONVM${NC}"
source ./build_testbed.sh

echo -e "${RED}Remember to checkout the onvm-upf to correct branch"
echo -e "And re-compile the onvm${NC}"
cd $HOME/onvm/onvm-upf
git checkout opensource
cd $HOME/onvm-upf/onvm
make
cd $HOME/onvm/onvm-upf/5gc/upf_c_complete
sudo rm -rf ./build; make
cd $HOME/onvm/onvm-upf/5gc/upf_u_complete
sudo rm -rf ./build; make

cd $HOME/L25GC-plus
sudo rm -rf $HOME/.cache
for nf in $NFs
do
    make $nf
done
