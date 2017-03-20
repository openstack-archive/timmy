#!/bin/bash

set -x

source $OPENRC
log='glance-image-upload.log'
rm $log
result="$(dd if=/dev/zero bs=1M count=4000 2>>$log | /usr/bin/time -f%e glance image-create --name "spt-test-image" --container-format bare --disk-format raw 2>>$log)"
cat $log
echo "$result"
rm $log
