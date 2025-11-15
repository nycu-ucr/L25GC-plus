#!/usr/bin/env bash

run_nf() {
    local name=$1
    local core=$2
    echo "Starting $name on core $core..."
    NF_NAME=$name sudo -E taskset -c $core ./bin/$name > log/${name}.log 2>&1 &
    sleep 2
}

mkdir -p log

run_nf nrf 5
run_nf amf 6
run_nf smf 7
run_nf udr 8
run_nf pcf 9
run_nf udm 10
run_nf nssf 11
run_nf ausf 12
run_nf chf 13

echo "All NFs started. Logs are in ./log/"
