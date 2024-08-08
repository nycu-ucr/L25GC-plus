#!/usr/bin/bash 
# UE/AN
export UEIF='ens1f0'
export UEIF_IP='192.168.1.1'
export UEIF_IP_ORIGIN='192.168.1.1'
export UEIF_SUBNET='192.168.1.0'
# DN
export DNIF='ens1f1'
export DNIF_IP='10.10.1.2'
export DNIF_IP_ORIGIN='192.168.1.4'
export DNIF_SUBNET='10.10.1.0'
# CN
export CNANIF='ens1f0'
export CNANIF_IP='192.168.1.2'
export CNANIF_MAC='3c:fd:fe:b4:ff:40'
export CNANIF_ORIGIN_IP='192.168.1.2'
export CNDNIF='ens1f1'
export CNDNIF_IP='10.10.1.1'
export CNDNIF_MAC='3c:fd:fe:b4:ff:41'
export CNDNIF_ORIGIN_IP='192.168.1.3'
# 5G constants
export UPF_IP='192.168.1.2'
export UE_IP='10.60.0.1'
export UE_INTERNAL_SUBNET='10.60.0.0'