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


def load_conf(filename):
    """Configuration parameters"""
    conf = {}
    conf['hard_filter'] = {}
    conf['soft_filter'] = {'status': ['ready', 'discover'], 'online': True}
    conf['ssh_opts'] = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                        '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                        '-lroot', '-oBatchMode=yes']
    conf['env_vars'] = ['OPENRC=/root/openrc', 'IPTABLES_STR="iptables -nvL"']
    conf['fuel_ip'] = '127.0.0.1'
    conf['fuel_user'] = 'admin'
    conf['fuel_pass'] = 'admin'
    conf['fuel_tenant'] = 'admin'
    conf['fuelclient'] = True  # use fuelclient library by default
    conf['fuel_skip_proxy'] = True
    conf['timeout'] = 15
    conf['prefix'] = 'nice -n 19 ionice -c 3'
    rqdir = 'rq'
    rqfile = 'rq.yaml'
    dtm = os.path.join(os.path.abspath(os.sep), 'usr', 'share', 'timmy')
    if os.path.isdir(os.path.join(dtm, rqdir)):
        conf['rqdir'] = os.path.join(dtm, rqdir)
    else:
        conf['rqdir'] = rqdir
    if os.path.isfile(os.path.join(dtm, 'configs', rqfile)):
        conf['rqfile'] = os.path.join(dtm, 'configs', rqfile)
    else:
        conf['rqfile'] = rqfile
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
    conf['logs'] = {'path': '/var/log',
                    'exclude': '\.[^12]\.gz$|\.\d{2,}\.gz$',
                    'start': '-30'}
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
