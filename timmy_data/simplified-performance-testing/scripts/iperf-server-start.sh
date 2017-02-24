#!/bin/bash

SPT_IPERF_PORT=${SPT_IPERF_PORT:-"65432"}

# install iperf
which iperf &>/dev/null
if [ "$?" -ne "0" ]
then
  result="$(DEBIAN_FRONTEND=noninteractive apt-get -y --force-yes install iperf 2>&1)"
  [ "$?" -ne "0" ] && echo -e "failed to install iperf:\n$result" && exit 1
fi

# add firewall rule
if [ "$(iptables -S | grep -c spt-temporary-rule-tcp-${SPT_IPERF_PORT})" -eq 0 ]
then
  result="$(iptables -I INPUT 1 -p tcp --dport ${SPT_IPERF_PORT} -j ACCEPT -m comment --comment "spt-temporary-rule-tcp-${SPT_IPERF_PORT}" 2>&1)"
  [ "$?" -ne "0" ] && echo -e "failed to add iptables rule:\n$result" && exit 1
fi

# start iperf server
outfile=$(mktemp)
iperf -s -p $SPT_IPERF_PORT &> $outfile &
printf $outfile
