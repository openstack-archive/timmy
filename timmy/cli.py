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
from timmy.tools import interrupt_wrapper


def pretty_run(quiet, msg, f, args=[], kwargs={}):
    if not quiet:
        sys.stdout.write('%s...\r' % msg)
        sys.stdout.flush()
    result = f(*args, **kwargs)
    if not quiet:
        print('%s: done' % msg)
    return result


@interrupt_wrapper
def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description=('Parallel remote command'
                                                  ' execution and file'
                                                  ' manipulation tool'))
    parser.add_argument('-c', '--conf',
                        help='Path to YAML a configuration file.')
    parser.add_argument('-j', '--nodes-json',
                        help=('Path to a json file retrieved via'
                              ' "fuel node --json". Useful to speed up'
                              ' initialization, skips "fuel node" call.'))
    parser.add_argument('-o', '--dest-file',
                        help=('Output filename for the archive in tar.gz'
                              ' format for command outputs and collected'
                              ' files. Overrides "archives" config option.'))
    parser.add_argument('--log-file', default=None,
                        help='Redirect Timmy log to a file.')
    parser.add_argument('-e', '--env', type=int,
                        help='Env ID. Run only on specific environment.')
    parser.add_argument('-R', '--role', action='append',
                        help=('Can be specified multiple times.'
                              ' Run only on the specified role.'))
    parser.add_argument('-G', '--get', action='append',
                        help=('Enables shell mode. Can be specified multiple'
                              ' times. Filemask to collect via "scp -r".'
                              ' Result is placed into a folder specified'
                              ' by "outdir" config option.'
                              ' For help on shell mode, read timmy/conf.py.'))
    parser.add_argument('-C', '--command', action='append',
                        help=('Enables shell mode. Can be specified'
                              ' multiple times. Shell command to execute.'
                              ' For help on shell mode, read timmy/conf.py.'))
    parser.add_argument('-S', '--script', action='append',
                        help=('Enables shell mode. Can be specified'
                              ' multiple times. Bash script name to execute.'
                              ' Script must be placed in "%s" folder inside'
                              ' a path specified by "rqdir" configuration'
                              ' parameter. For help on shell mode, read'
                              ' timmy/conf.py.') % Node.skey)
    parser.add_argument('-P', '--put', nargs=2, action='append',
                        help=('Enables shell mode. Can be specified multiple'
                              ' times. Upload filemask via"scp -r" to node(s).'
                              ' Each argument must contain two strings -'
                              ' source file/path/mask and dest. file/path.'
                              ' For help on shell mode, read timmy/conf.py.'))
    parser.add_argument('-l', '--logs',
                        help=('Collect logs from nodes. Logs are not collected'
                              ' by default due to their size.'),
                        action='store_true', dest='getlogs')
    parser.add_argument('--only-logs',
                        action='store_true',
                        help=('Only collect logs, do not run commands or'
                              ' collect files.'))
    parser.add_argument('--fake-logs',
                        help='Do not collect logs, only calculate size.',
                        action='store_true')
    parser.add_argument('-x', '--extended', action='store_true',
                        help='Execute extended commands.')
    parser.add_argument('--no-archive',
                        help=('Do not create results archive. By default,'
                              ' an archive with all outputs and files'
                              ' is created every time you run Timmy.'),
                        action='store_true')
    parser.add_argument('--no-clean',
                        help=('Do not clean previous results. Allows'
                              ' accumulating results across runs.'),
                        action='store_true')
    parser.add_argument('-q', '--quiet',
                        help=('Print only command execution results and log'
                              ' messages. Good for quick runs / "watch" wrap.'
                              ' Also sets default loglevel to ERROR.'),
                        action='store_true')
    parser.add_argument('-m', '--maxthreads', type=int, default=100,
                        help=('Maximum simultaneous nodes for command'
                              'execution.'))
    parser.add_argument('-L', '--logs-maxthreads', type=int, default=100,
                        help='Maximum simultaneous nodes for log collection.')
    parser.add_argument('-w', '--warning',
                        help='Sets log level to warning (default).',
                        action='store_true')
    parser.add_argument('-v', '--verbose',
                        help='Be verbose.',
                        action='store_true')
    parser.add_argument('-d', '--debug',
                        help='Be extremely verbose.',
                        action='store_true')
    args = parser.parse_args(argv[1:])
    if args.quiet and not args.warning:
        loglevel = logging.ERROR
    else:
        loglevel = logging.WARNING
    if args.verbose:
        loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG
    logging.basicConfig(filename=args.log_file,
                        level=loglevel,
                        format='%(asctime)s %(levelname)s %(message)s')
    conf = load_conf(args.conf)
    if args.put or args.command or args.script or args.get:
        conf['shell_mode'] = True
    if args.no_clean:
        conf['clean'] = False
    if conf['shell_mode']:
        filter = conf['hard_filter']
        # config cleanup for shell mode
        for k in Node.conf_actionable:
            conf[k] = [] if k in Node.conf_appendable else None
        for k in conf:
            if k.startswith(Node.conf_match_prefix):
                conf.pop(k)
        if args.put:
            conf[Node.pkey] = args.put
        if args.command:
            i = 0
            pad = str(len(str(len(args.command))))
            template = 'timmy_shell_mode_cmd_%0' + pad + 'd'
            for c in args.command:
                cmdname = template % i
                conf[Node.ckey].append({cmdname: c})
                i += 1
        if args.script:
            conf[Node.skey] = args.script
        if args.get:
            conf[Node.fkey] = args.get
    else:
        filter = conf['soft_filter']
    if args.role:
        filter['roles'] = args.role
    if args.env is not None:
        filter['cluster'] = [args.env]
    main_arc = os.path.join(conf['archives'], 'general.tar.gz')
    if args.dest_file:
        main_arc = args.dest_file
    nm = pretty_run(args.quiet, 'Initializing node data',
                    NodeManager,
                    kwargs={'conf': conf, 'extended': args.extended,
                            'nodes_json': args.nodes_json})
    if not args.only_logs:
        if nm.has(Node.pkey):
            pretty_run(args.quiet, 'Uploading files', nm.put_files)
        if nm.has(Node.ckey, Node.skey):
            pretty_run(args.quiet, 'Executing commands and scripts',
                       nm.run_commands, args=(conf['outdir'],
                                              args.maxthreads))
        if nm.has(Node.fkey, Node.flkey):
            pretty_run(args.quiet, 'Collecting files and filelists',
                       nm.get_files, args=(conf['outdir'], args.maxthreads))
        if not args.no_archive and nm.has(*Node.conf_archive_general):
            pretty_run(args.quiet, 'Creating outputs and files archive',
                       nm.create_archive_general, args=(conf['outdir'],
                                                        main_arc, 60))
    if args.only_logs or args.getlogs:
        size = pretty_run(args.quiet, 'Calculating logs size',
                          nm.calculate_log_size, args=(args.maxthreads,))
        if size == 0:
            logging.warning('Size zero - no logs to collect.')
            return
        enough = pretty_run(args.quiet, 'Checking free space',
                            nm.is_enough_space, args=(conf['archives'],))
        if enough:
            pretty_run(args.quiet, 'Collecting and packing logs', nm.get_logs,
                       args=(conf['archives'], conf['compress_timeout']),
                       kwargs={'maxthreads': args.logs_maxthreads,
                               'fake': args.fake_logs})
        else:
            logging.warning(('Not enough space for logs in "%s", skipping'
                             'log collection.') %
                            conf['archives'])
    logging.info("Nodes:\n%s" % nm)
    if not args.quiet:
        print('Run complete. Node information:')
        print(nm)
    if conf['shell_mode']:
        if args.command or args.script:
            if not args.quiet:
                print('Results:')
            for node in nm.sorted_nodes():
                node.print_results(node.mapcmds)
                node.print_results(node.mapscr)
    if nm.has(Node.fkey, Node.flkey) and not args.quiet:
        print('Outputs and files available in "%s".' % conf['outdir'])
    if all([not args.no_archive, nm.has(*Node.conf_archive_general),
            not args.quiet]):
        print('Archives available in "%s".' % conf['archives'])
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
