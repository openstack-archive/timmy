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

export LANG=C
export LC_ALL=C
export TERM=xterm

#cluster="7"

logd='logs'
rolesd='cmds'
infod='info'
reqdir='req-files'

filesd="${infod}/files"

# execution files template
template="tmp/"

# exec extended once-by-role
extended=1

nodesf="${infod}/nodes"
errlog="${logd}/error.log"
noticelog="${logd}/main.log"
sshopts="-oConnectTimeout=2 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oLogLevel=error -lroot -oBatchMode=yes"
env_timeout="25s" # ssh command timeout
sshvars="OPENRC=/root/openrc IPTABLES_STR='iptables -nvL'"
fuelip="localhost"

stemplate="timmy-snapshot"

# check and create directory
function ccdir
{
    [ ! -d "$1" ] && mkdir -p "$1/"
}

function nlog
{
    echo -e "$(date --utc) $1" | column -s "|" -t >> "$noticelog"
}

function elog
{
    echo -e "$(date --utc) $1" | column -s "|" -t >> "$errlog"
}
