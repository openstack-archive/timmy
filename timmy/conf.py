#!/usr/bin/env python2
# -*- coding: utf-8 -*-

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

from tools import load_yaml_file
from tempfile import gettempdir
import os
from pkg_resources import resource_filename as resource_fn
from timmy.env import project_name


def init_default_conf():
    """Configuration parameters"""
    conf = {}
    conf['hard_filter'] = {}
    conf['soft_filter'] = {}
    conf['ssh_opts'] = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                        '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                        '-oBatchMode=yes', '-oUser=root']
    conf['rsync_opts'] = ['-avzP', '--delete-before']
    conf['env_vars'] = ['OPENRC=/root/openrc', 'LC_ALL="C"', 'LANG="C"']
    conf['timeout'] = 30
    conf['prefix'] = 'nice -n 19 ionice -c 3'
    rqdir = 'rq'
    rqfile = 'default.yaml'
    data_package = '%s_data' % project_name
    conf['rqdir'] = os.path.join(resource_fn(data_package, rqdir))
    conf['rqfile'] = [{'file': os.path.join(conf['rqdir'], rqfile),
                      'default': True}]
    conf['compress_timeout'] = 3600
    conf['outdir'] = os.path.join(gettempdir(), 'timmy', 'info')
    conf['archive_dir'] = os.path.join(gettempdir(), 'timmy', 'archives')
    conf['archive_name'] = 'general.tar.gz'
    conf['outputs_timestamp'] = False
    conf['dir_timestamp'] = False
    conf['put'] = []
    conf['cmds'] = []
    conf['scripts'] = []
    conf['files'] = []
    conf['filelists'] = []
    conf['logs'] = []
    conf['logs_no_default'] = False  # skip logs defined in default.yaml
    conf['logs_days'] = 30
    conf['logs_speed_limit'] = False  # enable speed limiting of log transfers
    conf['logs_speed_default'] = 100  # Mbit/s, used when autodetect fails
    conf['logs_speed'] = 0  # To manually specify max bandwidth in Mbit/s
    conf['logs_size_coefficient'] = 1.05  # estimated logs compression ratio
    '''Shell mode - only run what was specified via command line.
    Skip actionable conf fields (see timmy/nodes.py -> Node.conf_actionable);
    Skip rqfile import;
    Skip any overrides (see Node.conf_match_prefix);
    Skip 'once' overrides (see Node.conf_once_prefix);
    Skip Fuel node;
    Print command execution results. Files and outputs will also be in a
    place specified by conf['outdir'], archive will also be created and put
    in a place specified by conf['archive_dir'].'''
    conf['shell_mode'] = False
    '''Print output of commands and scripts to stdout'''
    conf['do_print_results'] = False
    '''Clean - erase previous results in outdir and archive_dir dir, if any.'''
    conf['clean'] = True
    '''Analyze collected data and provide cluster health insight.'''
    conf['analyze'] = False
    '''Mark all nodes as inaccessible. Useful for offline analysis.'''
    conf['offline'] = False
    '''Limit the amount of workers which run simultanelously. Impacts all
    concurrent operations except log collection and client phase of
    scripts_all_pairs. Mandatory.'''
    conf['maxthreads'] = 100
    '''Limit the amount of workers which collect logs (one per node = the
    amount of nodes from which logs are simultaneously collected). Impacts
    only log collection routine. Mandatory.'''
    conf['logs_maxthreads'] = 10
    '''For each pair of nodes A & B only run client script on node A.
    Decreases the amount of iterations in scripts_all_pairs twice.'''
    conf['scripts_all_pairs_one_way'] = False
    '''How many pairs to process simultaneously. 0 = unlimited = num. nodes
    divided by 2. Limits concurrency for scripts_all_pairs client phase.'''
    conf['scripts_all_pairs_max_pairs'] = 0
    return conf


def update_conf(conf, filename):
    if filename is not None:
        conf_extra = load_yaml_file(filename)
        conf.update(**conf_extra)
    return conf


if __name__ == '__main__':
    import yaml
    conf = init_default_conf()
    conf = update_conf(conf, 'config.yaml')
    print(yaml.dump(conf))
