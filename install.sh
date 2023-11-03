#!/bin/bash -i

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

NFs="nrf amf smf udr pcf udm nssf ausf"

cd $HOME
sudo apt -y update
sudo apt -y install mongodb wget git
sudo systemctl start mongodb
sudo apt -y update
sudo apt -y install git gcc g++ cmake autoconf libtool pkg-config libmnl-dev libyaml-dev

cd $HOME/L25GC-plus
git submodule sync
git submodule update --init

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

echo "export ONVMPOLLER_IPID_YAML=$HOME/L25GC-plus/onvm_config_yaml/ipid.yaml" >> ~/.bashrc
echo "export ONVMPOLLER_NFIP_YAML=$HOME/L25GC-plus/onvm_config_yaml/NFip.yaml" >> ~/.bashrc
echo "export ONVMPOLLER_IPID_TXT=$HOME/L25GC-plus/onvm_config_yaml/ipid.txt" >> ~/.bashrc
echo "export CGO_LDFLAGS_ALLOW='-Wl,(--whole-archive|--no-whole-archive)'" >> ~/.bashrc
echo "export ONVM_NF_JSON=$HOME/onvm/NF_json/" >> ~/.bashrc
source ~/.bashrc

for i in $(seq 1 4)
do
    for nf in $NFs
    do
        rm -rf ~/.cache
        make $nf
        ./update_onvmpoller.sh
    done
done
cd $HOME

cd $HOME/L25GC-plus/onvm_test
sudo rm -rf ~/go/pkg/mod/github.com
sudo rm -rf ~/go/pkg/mod/cache
sudo rm -rf ~/.cache
go mod tidy
sudo rm -rf ~/.cache
cd $HOME/L25GC-plus
./update_onvmpoller.sh
cd $HOME/L25GC-plus/onvm_test
sudo rm -rf ~/.cache
go mod tidy

source ~/.bashrc