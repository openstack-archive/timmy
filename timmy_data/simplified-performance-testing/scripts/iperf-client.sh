#!/bin/bash

set -x

function timeout_kill() {
    if [ "$1" -gt 0 ]
    then
        sleep 10.5
        [ "$(pgrep iperf | grep -c "$1")" -gt 0 ] && sleep 5
        [ "$(pgrep iperf | grep -c "$1")" -gt 0 ] && kill -9 $1 &>/dev/null
    fi
}

SPT_IPERF_PORT=${SPT_IPERF_PORT:-"65432"}
[ -z "$SERVER_IP" ] && echo '$SERVER_IP not provided, exiting' && exit 1

# install iperf
which iperf &>/dev/null
if [ "$?" -ne "0" ]
then
    result="$(DEBIAN_FRONTEND=noninteractive apt-get -y install iperf 2>&1)"
    [ "$?" -ne "0" ] && echo -e "failed to install iperf:\n$result" && exit 1
fi

iperf -c $SERVER_IP -p $SPT_IPERF_PORT &
timeout_kill $!
iperf -c $SERVER_IP -p $SPT_IPERF_PORT -P10 &
timeout_kill $!
