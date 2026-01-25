#!/usr/bin/bash 
# UE/AN (external machine)
export UEIF='enp1s0f0'  # UE/gNB machine interface (not used on CN node)
export UEIF_IP='192.168.1.1'
export UEIF_IP_ORIGIN='192.168.1.1'
export UEIF_SUBNET='192.168.1.0'
# DN (external machine)
export DNIF='enp6s0f1'  # DN machine interface (not used on CN node)
export DNIF_IP='10.10.1.2'
export DNIF_IP_ORIGIN='192.168.1.4'
export DNIF_SUBNET='10.10.1.0'
# CN (THIS machine - Core Network/UPF)
export CNANIF='enp1s0f1'  # CN AN-side interface (will be bound to DPDK)
export CNANIF_IP='192.168.1.2'
export CNANIF_MAC='70:e4:22:83:d5:4f'  # enp1s0f1 MAC
export CNANIF_ORIGIN_IP=''  # No existing IP (interface is DOWN)
export CNDNIF='enp6s0f0'  # CN DN-side interface (will be bound to DPDK)
export CNDNIF_IP='10.10.1.1'
export CNDNIF_MAC='90:e2:ba:b5:03:a4'  # enp6s0f0 MAC
export CNDNIF_ORIGIN_IP='10.10.1.1'  # Current IP from ip a output
# 5G constants
export UPF_IP='192.168.1.2'
export UE_IP='10.60.0.1'
export UE_INTERNAL_SUBNET='10.60.0.0'