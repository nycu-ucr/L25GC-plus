#!/usr/bin/env bash
NF_NAME=nrf sudo -E taskset -c 5 ./bin/nrf &
sleep 2
NF_NAME=amf sudo -E taskset -c 6 ./bin/amf &
sleep 2
NF_NAME=smf sudo -E taskset -c 7 ./bin/smf &
sleep 2
NF_NAME=udr sudo -E taskset -c 8 ./bin/udr &
sleep 2
NF_NAME=pcf sudo -E taskset -c 9 ./bin/pcf &
sleep 2
NF_NAME=udm sudo -E taskset -c 10 ./bin/udm &
sleep 2
NF_NAME=nssf sudo -E taskset -c 11 ./bin/nssf &
sleep 2
NF_NAME=ausf sudo -E taskset -c 12 ./bin/ausf &
sleep 2