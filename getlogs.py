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

"""
main module
"""

import argparse
import logging
import sys
import nodes
import loadconf
import flock


def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='need to add description')
    parser.add_argument('-a', '--dest-file', default='/tmp/',
                        help='directory with output archive')
    parser.add_argument('-f', '--nodes',
                        help='nodes file', default='nodes.json')
    parser.add_argument('-t', '--timeout',
                        help='timeout for command', type=int, default=15)
    parser.add_argument('-l', '--log-dir',
                        help='log directory', default='./logs/')
    parser.add_argument('-e', '--extended', default="0",
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
    parser.add_argument('-d', '--debug',
                        help="Print lots of debugging statements",
                        action="store_const", dest="loglevel",
                        const=logging.DEBUG,
                        default=logging.WARNING,)
    parser.add_argument('-v', '--verbose',
                        help="Be verbose",
                        action="store_const", dest="loglevel",
                        const=logging.INFO,)

    args = parser.parse_args(argv[1:])
    logging.basicConfig(level=args.loglevel,
                        format='%(asctime)s %(levelname)s %(message)s')
    conf = loadconf.load_conf('config.yaml')
    args.extended = args.extended == "1"
    n = nodes.Nodes(filesd=conf['rqdir'],
                    logdir=conf['logdir'],
                    extended=args.extended,
                    fuelip=conf['fuelip'],
                    cluster=args.cluster,
                    sshopts=conf['ssh']['opts'],
                    sshvars=conf['ssh']['vars'],
                    timeout=conf['timeout'],
                    destdir=args.dest_file)
    lock = flock.FLock('/tmp/timmy-logs.lock')
    if not lock.lock():
        logging.warning('Unable to obtain lock, skipping "logs"-part')
    n.get_node_file_list()
    n.calculate_log_size(conf['find']['template'])
    if n.is_enough_space():
        n.get_log_files(conf['out-dir'])
        n.create_archive_logs(conf['find']['template'],
                              conf['logs-archive'],
                              conf['compress-timeout'])
        n.add_logs_archive(conf['out-dir'], nodes.lkey,
                           conf['logs-archive'], 120)
        n.compress_archive(conf['logs-archive'], conf['compress-timeout'])
    n.print_nodes()
    lock.unlock()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
