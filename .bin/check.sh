#!/usr/bin/env bash

# Go to the root dir first, so configs and vendor dir is found
cd $(git rev-parse --show-toplevel)

savedOutput=""

error () {
    local status=$1
    echo -e "\e[0;37;41mNOK\e[0m"
    echo -e "${savedOutput}\n"
    exit ${status}
}

success () {
    echo -e "\e[0;30;42mOK\e[0m"
}

runCheck () {
    local label=$1
    local command=$2

    echo -en "\e[0;37m- $(padTo "${label}" 25): \e[0m"
    savedOutput=$(eval "${command}") && success || error $?
}

padTo () {
    local string=$1
    local targetLen=$2

    len=$(echo -n "${string}" | wc -c)
    while [[ ${len} -lt ${targetLen} ]];
    do
        string=${string}"."
        let len=len+1
    done
    echo ${string}
}

echo -en "\n\e[0;37m###################\e[0m"
echo -en "\n\e[0;37m# Starting Checks #\e[0m"
echo -e "\n\e[0;37m###################\e[0m\n"

runCheck "golangci-lint"      "golangci-lint run"
runCheck "errcheck"   "errcheck -ignoretests ./..."
runCheck "tests"   "go test ./..."

echo -e "\n\n\e[0;37;42mAll checks completed successfully.\e[0m\n"
