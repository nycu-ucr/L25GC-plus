#!/usr/bin/env bash

cd ~/L25GC-plus/onvm_test

options=("TestRegistration" "TestMultiRegistrationConcurrent" 
"TestPaging" "TestMultiPagingConcurrent" 
"TestN2Handover" "TestMultiN2Handover" "TestMultiN2HandoverConcurrent" "Quit")

options_length=${#options[@]}

select opt in "${options[@]}"; do
    case $REPLY in
        [1-$((options_length-1))])
            selected_option="${options[REPLY - 1]}"
            echo -e "Now testing \e[33m$selected_option" 
            NF_NAME=tmp sudo -E /usr/local/go/bin/go test -v -vet=off -run $selected_option -args noinit
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






