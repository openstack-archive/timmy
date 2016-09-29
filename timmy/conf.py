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


def load_conf(filename):
    """Configuration parameters"""
    conf = {}
    conf['hard_filter'] = {}
    conf['soft_filter'] = {}
    conf['ssh_opts'] = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                        '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                        '-oBatchMode=yes', '-oUser=root']
    conf['env_vars'] = ['OPENRC=/root/openrc', 'LC_ALL="C"', 'LANG="C"']
    conf['fuel_ip'] = '127.0.0.1'
    conf['fuel_api_user'] = 'admin'
    conf['fuel_api_pass'] = 'admin'
    conf['fuel_api_token'] = None
    conf['fuel_api_tenant'] = 'admin'
    conf['fuel_api_port'] = '8000'
    conf['fuel_api_keystone_port'] = '5000'
    # The three parameters below are used to override FuelClient, API, CLI auth
    conf['fuel_user'] = None
    conf['fuel_pass'] = None
    conf['fuel_tenant'] = None

    conf['fuelclient'] = True  # use fuelclient library by default
    conf['fuel_skip_proxy'] = True
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
    conf['logs_fuel_remote_dir'] = ['/var/log/docker-logs/remote',
                                    '/var/log/remote']
    conf['logs_no_fuel_remote'] = False  # do not collect /var/log/remote
    '''Do not collect from /var/log/remote/<node>
    if node is in the array of nodes filtered out by soft filter'''
    conf['logs_exclude_filtered'] = True
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
    if filename:
        conf_extra = load_yaml_file(filename)
        conf.update(**conf_extra)
    return conf


if __name__ == '__main__':
    import yaml
    conf = load_conf('config.yaml')
    print(yaml.dump(conf))
