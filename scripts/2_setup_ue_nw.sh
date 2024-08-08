#!/usr/bin/bash
# Include NW settings
. ./set_nw_env.sh

# Modify IP
sudo ip l set dev $UEIF down
sudo ip a del $UEIF_IP_ORIGIN/24 dev $UEIF
sudo ip a add $UEIF_IP/24 dev $UEIF
sudo ip l set dev $UEIF up

# Set essential IP routes and ARP entries
sudo ip r add $DNIF_SUBNET/24 dev $UEIF
sudo arp -s $DNIF_IP $CNANIF_MAC
sudo arp -s $UPF_IP $CNANIF_MAC
