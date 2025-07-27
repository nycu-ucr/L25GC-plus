#!/usr/bin/bash

WORK_DIR=$HOME

# Include NW settings
. $WORK_DIR/L25GC-plus/scripts/set_nw_env.sh

# Modify IP
sudo ip l set $DNIF down
sudo ip a del $DNIF_IP_ORIGIN/24 dev $DNIF
sudo ip a add $DNIF_IP/24 dev $DNIF
sudo ip l set $DNIF up

# Set essential IP routes and ARP entries
sudo ip r add $UEIF_SUBNET/24 dev $DNIF
sudo arp -s $UEIF_IP $CNDNIF_MAC
sudo ip r add $UE_INTERNAL_SUBNET/24 dev $DNIF
sudo arp -s $UE_IP $CNDNIF_MAC
