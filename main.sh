#!/bin/bash

#    Copyright 2015 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Set environment variables for the environment
source ./env.sh

[ -e $mainlog ] && cat $mainlog >> $mainlog.old && rm -f $mainlog

# Command which should be lauched on master node
source ./local.sh

# Get list nodes
source ./get_nodes.sh
release=`cat /etc/nailgun/version.yaml | awk '/release/ {print $2}' | tr -d '"'`

# Run the parser nodes
./prepare.py --nodes "${nodesf}.json" --cluster "$cluster" --template "$template" --rolesd "$rolesd" --extended="$extended" --fuel-version="$release" --req-files="$reqdir"| column -t > "${nodesf}.txt"

nodef="${nodesf}.txt"

function getoutput {
    cmdfile=$1
    fnode=$2
    fip=$3
    roled=`dirname $cmdfile`
    role=`basename $roled`
    clogd="$infod/outputs/cluster-${cluster}/node-$fnode"
    ccdir $clogd
    logf="$clogd/node-$fnode-$fip-$role-`basename $cmdfile`.log"
    logm="|cluster: ${cluster}|node-$fnode|($fip):|Failed to execute: $cmdfile, see $logf"
    cat $cmdfile | timeout $env_timeout ssh $sshopts -t -T  $fip $sshvars "bash -s " &> \
    $logf || echo -e `date --utc`$logm | column -s "|" -t >> $mainlog

}

for ip in `awk '!/^#/ {print $3}' "${nodef}"`
do
    node=`egrep $ip $nodef | awk '{print $1}'`
    cluster=`egrep $ip $nodef | awk '{print $2}'`
    fd=${filesd}/cluster-${cluster}/node-${node}-${ip}
    ccdir $fd
    for cmdfile in `cat "${template}${ip}-cmds.txt" | egrep -v "^#" | sort`
    do
        getoutput $cmdfile $node $ip
    done & ### launches ssh on all nodes in parallel by send the process in background

    # request files from nodes
    for rfile in `cat "${template}${ip}-files.txt" | egrep -v "^#" | sort`
    do
        tf="${template}${ip}-allfiles"
        cat $rfile >> $tf
        grep -v "^#" $tf | sort | uniq > $tf.tmp
        mv $tf.tmp $tf
        # Copy log files from nodes
        rsync -avz -e "ssh $sshopts" --files-from "$tf" ${ip}:/ ${fd} --delete-before --progress --partial &> ${logd}/node-${node}-${ip}-files.log
    done &
done

#jobs -l
wait

[ -e $mainlog ] && echo "something went wrong, see $mainlog file" && tail $mainlog

source ./create-arc.sh
