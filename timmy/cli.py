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
from timmy.nodes import NodeManager
import logging
import sys
import os
from timmy.conf import Conf
from timmy import flock
from timmy.tools import interrupt_wrapper


@interrupt_wrapper
def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description=('Parallel remote command'
                                                  ' execution and file'
                                                  ' collection tool'))
    parser.add_argument('--config',
                        help='config file')
    parser.add_argument('-o', '--dest-file',
                        help='output archive file')
    parser.add_argument('-e', '--extended', action='store_true',
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
    parser.add_argument('-l', '--logs',
                        help='collect logs from nodes',
                        action='store_true', dest='getlogs')
    parser.add_argument('-L', '--logs-maxthreads', type=int, default=100,
                        help="maximum simultaneous log collection operations")
    parser.add_argument('--only-logs',
                        action='store_true',
                        help='Collect only logs from fuel-node')
    parser.add_argument('--log-file', default=None,
                        help='timmy log file')
    parser.add_argument('--fake-logs',
                        help="Do not collect logs, only calculate size",
                        action="store_true")
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
    logging.basicConfig(filename=args.log_file,
                        level=loglevel,
                        format='%(asctime)s %(levelname)s %(message)s')
    config = Conf()
    if args.config:
        config = Conf.load_conf(args.config)
    main_arc = os.path.join(config.archives, 'general.tar.bz2')
    if args.dest_file:
        main_arc = args.dest_file
    n = NodeManager(conf=config,
                    extended=args.extended,
                    cluster=args.cluster,
                    )
    if not args.only_logs:
        n.get_node_file_list()
        n.launch_ssh(config.outdir)
        n.get_conf_files(config.outdir)
        n.create_archive_general(config.outdir,
                                 main_arc,
                                 60)
    if args.only_logs or args.getlogs:
        lf = '/tmp/timmy-logs.lock'
        lock = flock.FLock(lf)
        if lock.lock():
           n.get_node_file_list()
           n.calculate_log_size()
           if n.is_enough_space(config.archives):
               n.archive_logs(config.archives,
                              config.compress_timeout,
                              maxthreads=args.logs_maxthreads,
                              fake=args.fake_logs)
           lock.unlock()
        else:
            logging.warning('Unable to obtain lock %s, skipping "logs"-part' %
                            lf)
    logging.info("Nodes:\n%s" % n)
    print(n)
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
