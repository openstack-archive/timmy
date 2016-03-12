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

import argparse
import nodes
import logging
import sys
from conf import Conf
import flock

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description=('Parallel remote command'
                                                  ' execution and file'
                                                  ' collection tool'))
    parser.add_argument('--config', default='config.yaml',
                        help='config file')
    parser.add_argument('-o', '--dest-file', default='/tmp/',
                        help='output archive file')
    # The following parameter has not been implemented yet.
    parser.add_argument('-f', '--nodes',
                        help='nodes file', default='nodes.json')
    parser.add_argument('-e', '--extended', action='store_true',
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
    parser.add_argument('-l', '--logs',
                        help='collect logs from fuel node',
                        action='store_true', dest='getlogs')
    parser.add_argument('--only-logs',
                        action='store_true',
                        help='Collect only logs from fuel-node')
    parser.add_argument('-d', '--debug',
                        help="print lots of debugging statements, implies -v",
                        action="store_true")
    parser.add_argument('-v', '--verbose',
                        help="be verbose",
                        action="store_true")
    args = parser.parse_args(argv[1:])
    loglevel = logging.WARNING
    if args.verbose:
        if args.debug:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO
    logging.basicConfig(level=loglevel,
                        format='%(asctime)s %(levelname)s %(message)s')
    config = Conf.load_conf(args.config)
    n = nodes.Nodes(conf=config,
                    extended=args.extended,
                    cluster=args.cluster,
                    destdir=args.dest_file)
    # nodes.print_nodes()
    if not args.only_logs:
        n.get_node_file_list()
        n.launch_ssh(config.outdir)
        n.get_conf_files(config.outdir)
        n.create_archive_general(config.outdir, '/tmp/timmy-gen.tar.bz2', 60)
    if args.only_logs or args.getlogs:
        lock = flock.FLock('/tmp/timmy-logs.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "logs"-part')
            return 1
        n.get_node_file_list()
        n.set_template_for_find()
        n.calculate_log_size(config.find['template'])
        if n.is_enough_space():
            n.get_log_files(config.outdir)
            n.create_archive_logs(config.archives,
                                  config.compress_timeout)
            n.add_logs_archive(config.outdir, nodes.lkey,
                               config.logs_archive, 120)
            n.compress_archive(config.logs_archive, config.compress_timeout)

    n.print_nodes()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
