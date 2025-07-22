#!/bin/bash

NFs="(mgr)|(amf)|(nrf)|(ausf)|(udm)|(udr)|(pcf)|(nssf)|(smf)|(chf)|(upf)"
simple="(\./server)|(\./client)"
http="(\./http_server)|(\./http_client)"
tp="(\./tp_server)|(\./tp_client)"

ps -aux | egrep "$NFs|$simple|$http|$tp" | awk '{print $2}' | xargs -n 2 sudo kill -9

tmux kill-session -t l25gc
sudo ip link del upfgtp
sudo rm /dev/mqueue/*
sudo rm -f /tmp/free5gc_unix_sock
mongo --eval "db.NfProfile.drop();db.applicationData.influenceData.subsToNotify.drop();db.applicationData.subsToNotify.drop();db.policyData.subsToNotify.drop();db.exposureData.subsToNotify.drop()" free5gc
mongosh --eval "db.NfProfile.drop();db.applicationData.influenceData.subsToNotify.drop();db.applicationData.subsToNotify.drop();db.policyData.subsToNotify.drop();db.exposureData.subsToNotify.drop()" free5gc