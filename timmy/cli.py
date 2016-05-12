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
from timmy.nodes import Node, NodeManager
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
                        help='Path to YAML a configuration file.')
    parser.add_argument('-o', '--dest-file',
                        help='Path to an output archive file.')
    parser.add_argument('-x', '--extended', action='store_true',
                        help='Execute extended commands.')
    parser.add_argument('-e', '--env', type=int,
                        help='Env ID. Run only on specific environment.')
    parser.add_argument('-m', '--maxthreads', type=int, default=100,
                        help=('Maximum simultaneous nodes for command'
                              'execution.'))
    parser.add_argument('-l', '--logs',
                        help=('Collect logs from nodes. Logs are not collected'
                              ' by default due to their size.'),
                        action='store_true', dest='getlogs')
    parser.add_argument('-L', '--logs-maxthreads', type=int, default=100,
                        help='Maximum simultaneous nodes for log collection.')
    parser.add_argument('--only-logs',
                        action='store_true',
                        help='Only collect logs, do not run commands.')
    parser.add_argument('--log-file', default=None,
                        help='Output file for Timmy log.')
    parser.add_argument('--fake-logs',
                        help='Do not collect logs, only calculate size.',
                        action='store_true')
    parser.add_argument('-d', '--debug',
                        help='Be extremely verbose.',
                        action='store_true')
    parser.add_argument('-v', '--verbose',
                        help='Be verbose.',
                        action='store_true')
    parser.add_argument('-C', '--command',
                        help=('Enables shell mode. Shell command to'
                              ' execute. For help on shell mode, read'
                              ' timmy/conf.py'))
    parser.add_argument('-F', '--file', nargs='+',
                        help=('Enables shell mode. Files to collect via'
                              '"scp -r". Result is placed into a folder'
                              'specified via "outdir" config option.'))
    parser.add_argument('-R', '--role', nargs='+',
                        help=('run only on the specified role(s). Example:'
                              ' -R compute ceph-osd any-other-role'))
    parser.add_argument('--no-archive',
                        help=('Do not create results archive. By default,'
                              ' an arhive with all outputs and files'
                              ' is created every time you run Timmy.'),
                        action='store_true')
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
    if args.command or args.file or conf['shell_mode']:
        conf['shell_mode'] = True
        # config cleanup for shell mode
        for k in Node.conf_actionable:
            conf[k] = [] if k in Node.conf_appendable else None
        for k in conf:
            if k.startswith(Node.conf_match_prefix):
                conf.pop(k)
        if args.command:
            conf[Node.ckey] = [{'stdout': args.command}]
        if args.file:
            conf[Node.fkey] = args.file
    if conf['shell_mode']:
        filter = conf['hard_filter']
    else:
        filter = conf['soft_filter']
    if args.role:
        filter['roles'] = args.role
    if args.env is not None:
        filter['cluster'] = [args.env]
    main_arc = os.path.join(conf['archives'], 'general.tar.gz')
    if args.dest_file:
        main_arc = args.dest_file
    nm = NodeManager(conf=conf,
                     extended=args.extended)
    if not args.only_logs:
        nm.run_commands(conf['outdir'], args.maxthreads)
        nm.get_files(conf['outdir'], args.maxthreads)
        if not args.no_archive:
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
                nm.get_logs(conf['archives'],
                            conf['compress_timeout'],
                            maxthreads=args.logs_maxthreads,
                            fake=args.fake_logs)
            lock.unlock()
        else:
            logging.warning('Unable to obtain lock %s, skipping "logs"-part' %
                            lf)
    logging.info("Nodes:\n%s" % nm)
    print('Run complete. Node information:')
    print(nm)
    if conf['shell_mode']:
        print('Results:')
        for node in nm.nodes.values():
            for cmd, path in node.mapcmds.items():
                with open(path, 'r') as f:
                    for line in f.readlines():
                        print('node-%s: %s' % (node.id, line.rstrip('\n')))
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
