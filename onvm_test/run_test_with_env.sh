#!/bin/bash
# Test runner with proper environment setup for L25GC+ ONVM

# Go environment
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

# ONVM environment
export ONVM_NF_JSON=$HOME/L25GC-plus/onvm_nf_configs/
export ONVMPOLLER_IPID_YAML=$HOME/L25GC-plus/onvm_test/ipid.yaml
export ONVMPOLLER_NFIP_YAML=$HOME/L25GC-plus/onvm_test/NFip.yaml
export ONVMPOLLER_IPID_TXT=$HOME/L25GC-plus/onvm_nf_configs/ipid.txt

echo "========================================="
echo "Running L25GC+ TestN2Handover"
echo "========================================="
echo "Environment:"
echo "  ONVM_NF_JSON: $ONVM_NF_JSON"
echo "  ONVMPOLLER_IPID_YAML: $ONVMPOLLER_IPID_YAML"
echo "  ONVMPOLLER_NFIP_YAML: $ONVMPOLLER_NFIP_YAML"
echo ""

cd ~/L25GC-plus/onvm_test
go test -v handover_test.go registration_test.go -run TestN2Handover

