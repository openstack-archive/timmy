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
from timmy.conf import load_conf
from timmy import flock
from timmy.tools import interrupt_wrapper


@interrupt_wrapper
def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description=('Parallel remote command'
                                                  ' execution and file'
                                                  ' collection tool'))
    parser.add_argument('-c', '--conf',
                        help='configuration file')
    parser.add_argument('-o', '--dest-file',
                        help='output archive file')
    parser.add_argument('-x', '--extended', action='store_true',
                        help='exec once by role cmdfiles')
    parser.add_argument('-e', '--env', help='env id', type=int)
    parser.add_argument('-m', '--maxthreads', type=int, default=100,
                        help="maximum simultaneous operations for commands")
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
    loglevel = logging.ERROR
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG
    logging.basicConfig(filename=args.log_file,
                        level=loglevel,
                        format='%(asctime)s %(levelname)s %(message)s')
    conf = load_conf(args.conf)
    if args.env is not None:
        conf['soft_filter']['cluster'] = [args.env]
    main_arc = os.path.join(conf['archives'], 'general.tar.gz')
    if args.dest_file:
        main_arc = args.dest_file
    nm = NodeManager(conf=conf,
                     extended=args.extended)
    if not args.only_logs:
        nm.launch_ssh(conf['outdir'], args.maxthreads)
        nm.get_conf_files(conf['outdir'], args.maxthreads)
        nm.create_archive_general(conf['outdir'],
                                  main_arc,
                                  60)
    if args.only_logs or args.getlogs:
        lf = '/tmp/timmy-logs.lock'
        lock = flock.FLock(lf)
        if lock.lock():
            size = nm.calculate_log_size(args.maxthreads)
            if size == 0:
                logging.warning('No logs to collect.')
                return
            if nm.is_enough_space(conf['archives']):
                nm.archive_logs(conf['archives'],
                                conf['compress_timeout'],
                                maxthreads=args.logs_maxthreads,
                                fake=args.fake_logs)
            lock.unlock()
        else:
            logging.warning('Unable to obtain lock %s, skipping "logs"-part' %
                            lf)
    logging.info("Nodes:\n%s" % nm)
    print(nm)
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
