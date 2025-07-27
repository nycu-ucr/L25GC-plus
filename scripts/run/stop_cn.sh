#!/bin/bash
set -e

# Define regex patterns to match relevant NF and client/server processes
NF_PROCESSES="(mgr|amf|nrf|ausf|udm|udr|pcf|nssf|smf|chf|upf)"
# SIMPLE_PROCESSES="(./server|./client)"
# HTTP_PROCESSES="(./http_server|./http_client)"
# TP_PROCESSES="(./tp_server|./tp_client)"

# Kill matching processes
echo "Killing NF and test processes..."
pids=$(ps -eo pid,cmd | egrep "$NF_PROCESSES" | awk '{print $1}')
if [ -n "$pids" ]; then
    echo "$pids" | xargs -r sudo kill -9
fi

# Kill tmux session if it exists
# tmux has-session -t l25gc 2>/dev/null && tmux kill-session -t l25gc

# Delete GTP link if it exists
# sudo ip link del upfgtp 2>/dev/null

# Clean IPC queues and UNIX domain socket
# sudo rm -f /dev/mqueue/* 2>/dev/null
# sudo rm -f /tmp/free5gc_unix_sock

# Clear MongoDB data for Free5GC
echo "Dropping MongoDB collections..."
mongosh --quiet --eval '
db.getSiblingDB("free5gc").NfProfile.drop();
db.getSiblingDB("free5gc").applicationData.influenceData.subsToNotify.drop();
db.getSiblingDB("free5gc").applicationData.subsToNotify.drop();
db.getSiblingDB("free5gc").policyData.subsToNotify.drop();
db.getSiblingDB("free5gc").exposureData.subsToNotify.drop();
'

echo "Cleanup complete."
