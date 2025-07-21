#!/usr/bin/env bash

cd ~/L25GC-plus/onvm_test

options=("TestRegistration" "TestMultiRegistrationConcurrent" "TestMultiPagingConcurrent" 
"TestN2Handover" "TestMultiN2HandoverConcurrent" "Quit")

options_length=${#options[@]}

select opt in "${options[@]}"; do
    case $REPLY in
        [1-$((options_length-1))])
            selected_option="${options[REPLY - 1]}"
            echo -e "Now testing \e[33m$selected_option\e[0m" 
            if [[ $selected_option == *"Concurrent"* ]]; then
                read -p "Input thread_amount " thread_amount
                read -p "Input work_load " work_load
                if [[ $selected_option == "TestMultiRegistrationConcurrent" ]]; then
                    read -p "Need Wait [y/n]? " is_wait
                    if [[ $is_wait == "y" ]]; then
                        read -p "Input wait_time (millisecond) " wait_time
                        NF_NAME=tmp sudo -E /usr/local/go/bin/go test -v -vet=off -run $selected_option -args noinit $thread_amount $work_load $is_wait $wait_time
                    else
                        NF_NAME=tmp sudo -E /usr/local/go/bin/go test -v -vet=off -run $selected_option -args noinit $thread_amount $work_load $is_wait
                    fi
                else
                    NF_NAME=tmp sudo -E /usr/local/go/bin/go test -v -vet=off -run $selected_option -args noinit $thread_amount $work_load 
                fi
            else
                NF_NAME=tmp sudo -E /usr/local/go/bin/go test -v -vet=off -run $selected_option -args noinit
            fi
            break
            ;;
        $((options_length)))
            echo "Quitting..."
            break
            ;;
        *) 
            echo "Invalid option"
            ;;
    esac
done
