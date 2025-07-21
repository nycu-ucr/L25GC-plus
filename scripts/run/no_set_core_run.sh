#!/usr/bin/env bash
NF_NAME=nrf sudo -E ./bin/nrf &
sleep 2
NF_NAME=amf sudo -E ./bin/amf &
sleep 2
NF_NAME=smf sudo -E ./bin/smf &
sleep 2
NF_NAME=udr sudo -E ./bin/udr &
sleep 2
NF_NAME=pcf sudo -E ./bin/pcf &
sleep 2
NF_NAME=udm sudo -E ./bin/udm &
sleep 2
NF_NAME=nssf sudo -E ./bin/nssf &
sleep 2
NF_NAME=ausf sudo -E ./bin/ausf &
sleep 2
