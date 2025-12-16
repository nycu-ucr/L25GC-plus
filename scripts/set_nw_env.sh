#!/usr/bin/bash 

# UE/AN
export UEIF="enp94s0f1"
export UEIF_IP_ORIGIN="192.168.1.1"
export UEIF_IP="192.168.1.1"
export UEIF_SUBNET="192.168.1.0"

# DN
export DNIF='enp94s0f0'
export DNIF_IP='192.168.1.4'
export DNIF_IP_ORIGIN='192.168.1.4'
export DNIF_SUBNET='192.168.1.0'

# CN
export CNANIF='enp94s0f1'
export CNANIF_IP='192.168.1.2'
export CNANIF_MAC='3c:fd:fe:b3:17:4d'
export CNANIF_ORIGIN_IP='192.168.1.2'
export CNDNIF='enp94s0f0'
export CNDNIF_IP='192.168.1.3'
export CNDNIF_MAC='3c:fd:fe:b3:17:4c'
export CNDNIF_ORIGIN_IP='192.168.1.3'

# 5G constants
export UPF_IP='192.168.1.2'
export UE_IP='10.60.0.1'
export UE_INTERNAL_SUBNET='10.60.0.0'