#!/bin/bash
# L25GC+ N2 Handover Test Runner Script
# This script starts the 5G core, runs the test, and stops the core

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}L25GC+ N2 Handover Test Runner${NC}"
echo -e "${GREEN}======================================${NC}\n"

# Set Go environment
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

# Set ONVM Poller config paths (required by onvmpoller package)
export ONVMPOLLER_IPID_YAML=$HOME/L25GC-plus/onvm_test/ipid.yaml
export ONVMPOLLER_NFIP_YAML=$HOME/L25GC-plus/onvm_test/NFip.yaml

# Step 1: Check if 5G Core is already running
echo -e "${YELLOW}[1/4] Checking for running 5G Core NFs...${NC}"
if pgrep -u $(whoami) "(amf|nrf|smf|udm|udr|pcf|nssf|ausf|chf)" > /dev/null; then
    echo -e "${YELLOW}Warning: 5G Core NFs are already running${NC}"
    echo -e "Would you like to stop and restart them? (Press Ctrl+C to cancel)"
    sleep 3
    cd ~/L25GC-plus
    ./scripts/run/stop_cn.sh
    sleep 2
fi

# Step 2: Start 5G Core Network
echo -e "\n${YELLOW}[2/4] Starting 5G Core Network...${NC}"
cd ~/L25GC-plus
./scripts/run/run_cp_nfs.sh > /dev/null 2>&1 &
echo -e "${GREEN}✓ Core Network Functions started${NC}"
echo "Waiting for NFs to initialize..."
sleep 5

# Step 3: Verify NFs are running
echo -e "\n${YELLOW}[3/4] Verifying NFs status...${NC}"
RUNNING_NFS=$(ps aux | grep -E "(nrf|amf|smf|udm|udr|pcf|nssf|ausf|chf)" | grep -v grep | wc -l)
if [ "$RUNNING_NFS" -lt 8 ]; then
    echo -e "${RED}✗ Error: Not all NFs are running (found $RUNNING_NFS/9)${NC}"
    echo "Please check logs in ~/L25GC-plus/log/"
    exit 1
fi
echo -e "${GREEN}✓ All NFs are running ($RUNNING_NFS/9)${NC}"

# Step 4: Run the test
echo -e "\n${YELLOW}[4/4] Running N2 Handover Test...${NC}"
echo -e "${GREEN}======================================${NC}\n"
cd ~/L25GC-plus/onvm_test
go test -v -run TestN2Handover

# Capture test result
TEST_RESULT=$?

echo -e "\n${GREEN}======================================${NC}"
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ Test PASSED${NC}"
else
    echo -e "${RED}✗ Test FAILED${NC}"
fi
echo -e "${GREEN}======================================${NC}\n"

# Clean up
echo -e "${YELLOW}Stopping 5G Core Network...${NC}"
cd ~/L25GC-plus
./scripts/run/stop_cn.sh

echo -e "${GREEN}✓ Test complete!${NC}"
exit $TEST_RESULT

