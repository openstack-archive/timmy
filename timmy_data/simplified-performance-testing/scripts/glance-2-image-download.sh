#!/bin/bash

set -x

source $OPENRC
id=$(glance image-list | grep "spt-test-image" | cut -d' ' -f2)
/usr/bin/time -f%e glance image-download $id 2>&1 > /dev/null
glance image-delete $id
