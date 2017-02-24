#!/bin/bash

SPT_IPERF_PORT=${SPT_IPERF_PORT:-"65432"}

killall -9 iperf
while [ "$(iptables -L --line-numbers | grep -c 'spt-temporary-rule')" -gt 0 ]
do
  rulenum=`iptables -L --line-numbers | grep 'spt-temporary-rule' | head -n 1 | awk '{print $1}'`
  [ -n "$rulenum" ] && [ "$rulenum" -ge 0 ] && iptables -D INPUT $rulenum
done
if [ -n $SERVER_OUTPUT ]
then
  echo $SERVER_OUTPUT
  cat $SERVER_OUTPUT
  rm -f $SERVER_OUTPUT
else
  echo '$SERVER_OUTPUT not provided'
fi
