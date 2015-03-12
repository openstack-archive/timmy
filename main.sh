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

[ -e $errlog ] && cat $errlog >> $errlog.old && rm -f $errlog
[ -e $noticelog ] && cat $noticelog >> $noticelog.old && rm -f $noticelog

command -v rsync > /dev/null 2>&1 || { nlog "rsync is not installed. "; elog "rsync is not installed"; }

nlog "local"
# Command which should be lauched on local node
source ./local.sh

# Get list nodes
nlog "get node list from fuel"
source ./get_nodes.sh

nlog "get release of fuel"
release=`ssh ${sshopts} ${fuelip} "cat /etc/nailgun/version.yaml" | awk '/release/ {print $2}' | tr -d '"'`

# Run the parser nodes
nlog "create node's list and related files"
./prepare.py \
    --nodes "${nodesf}.json" \
    --cluster "$cluster" \
    --template "$template" \
    --rolesd "$rolesd" \
    --extended="$extended" \
    --fuel-version="$release" \
    --req-files="$reqdir" \
    --admin-ip ${fuelip} | column -t > "${nodesf}.txt" || exit 1

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
    $logf || elog "$logm"

}

function getfiles {
    dfile=$1 # file-list destination file
    fip=$2 # node ip
    fnode=$3 # node id
    destd=$4 # destination directory
    egrep -v "^#|^[[:space:]]*$" $dfile | sort | uniq > $dfile.tmp
    mv $dfile.tmp $dfile
    logf="${logd}/node-${fnode}-${fip}-files.log"
    logm="|cluster: ${cluster}|node-$fnode|($fip):|rsync failed: $dfile, see $logf"
    command -v rsync &> /dev/null && \
    rsync -avzr -e "ssh $sshopts" --files-from "$dfile" ${fip}:/ ${destd} \
          --delete-before --progress --partial &> $logf || nlog "$logm"
}

nlog "launch remote commands and rsync on nodes"
for ip in `awk '!/^#/ {print $3}' "${nodef}"`
do
    node=`egrep $ip $nodef | awk '{print $1}'`
    cluster=`egrep $ip $nodef | awk '{print $2}'`
    fd="${filesd}/cluster-${cluster}/node-${node}-${ip}/"
    ccdir $fd #create destination directory
    for cmdfile in `cat "${template}${ip}-cmds.txt" | egrep -v "^#" | sort`
    do
        getoutput $cmdfile $node $ip
    done & ### launches ssh on all nodes in parallel by send the process in background

    # request files from nodes
    tf="${template}${ip}-allfiles"
    echo -n > $tf
    for rfile in `cat "${template}${ip}-files.txt" | egrep -v "^#" | sort`
    do
        cat $rfile >> $tf
        echo >> $tf #avoid glue strings
    done
    getfiles $tf $ip $node $fd & #launch rsync
done

#jobs -l
wait #wait for finish all background processes

[ -e $errlog ] && echo "something went wrong, see $errlog file" && tail $errlog

nlog "Create archives"
source ./create-arc.sh

nlog "Done. Results are stored into '$infod'"
