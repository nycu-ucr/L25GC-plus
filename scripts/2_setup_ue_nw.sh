#!/usr/bin/bash
WORK_DIR=$HOME

# Include NW settings
. $WORK_DIR/L25GC-plus/scripts/set_nw_env.sh

# Modify IP
sudo ip l set dev $UEIF down
sudo ip a del $UEIF_IP_ORIGIN/24 dev $UEIF
sudo ip a add $UEIF_IP/24 dev $UEIF
sudo ip l set dev $UEIF up

# Set essential IP routes and ARP entries
sudo ip r add $DNIF_SUBNET/24 dev $UEIF
sudo arp -s $DNIF_IP $CNANIF_MAC
sudo arp -s $UPF_IP $CNANIF_MAC
