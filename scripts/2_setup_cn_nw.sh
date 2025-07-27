#!/usr/bin/bash

WORK_DIR=$HOME

# Include NW settings
. $WORK_DIR/L25GC-plus/scripts/set_nw_env.sh

# Modify IP
sudo ip l set $CNANIF down
sudo ip l set $CNDNIF down
sudo ip a del $CNANIF_ORIGIN_IP/24 dev $CNANIF
sudo ip a del $CNDNIF_ORIGIN_IP/24 dev $CNDNIF
sudo ip a add $CNANIF_IP/24 dev $CNANIF
sudo ip a add $CNDNIF_IP/24 dev $CNDNIF
sudo ip l set $CNANIF up
sudo ip l set $CNDNIF up

# Bind DPDK NICs
# sudo ifconfig $CNANIF down
# sudo ifconfig $CNDNIF down
# sudo $HOME/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py --bind=igb_uio $ANIF_DEV $DNIF_DEV
