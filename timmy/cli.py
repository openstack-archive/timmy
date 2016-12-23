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

from timmy.analyze import analyze, analyze_print_results
from timmy.env import project_name, version
from timmy.nodes import Node
from timmy.tools import signal_wrapper
import argparse
import logging
import logging.handlers
import os
import sys


def pretty_run(quiet, msg, f, args=[], kwargs={}):
    if not quiet:
        sys.stdout.write('%s...\r' % msg)
        sys.stdout.flush()
    result = f(*args, **kwargs)
    if not quiet:
        print('%s: done' % msg)
    return result


def add_args(parser, module):
    parser = module.add_args(parser)
    return parser


def parser_init(add_help=False):
    desc = 'Parallel remote command execution and file manipulation tool'
    parser = argparse.ArgumentParser(description=desc, add_help=add_help)
    parser.add_argument('-V', '--version', action='store_true',
                        help='Print Timmy version and exit.')
    parser.add_argument('-c', '--config',
                        help='Path to a YAML configuration file.')
    parser.add_argument('-o', '--dest-file',
                        help=('Output filename for the archive in tar.gz'
                              ' format for command outputs and collected'
                              ' files. Overrides "archive_" config options.'
                              ' If logs are collected they will be placed'
                              ' in the same folder (but separate archives).'))
    parser.add_argument('--log-file', default=None,
                        help='Redirect Timmy log to a file.')
    parser.add_argument('-e', '--env', type=int,
                        help='Env ID. Run only on specific environment.')
    parser.add_argument('-r', '--role', action='append',
                        help=('Can be specified multiple times.'
                              ' Run only on the specified role.'))
    parser.add_argument('-i', '--id', type=int, action='append',
                        help=('Can be specified multiple times.'
                              ' Run only on the node(s) with given IDs.'))
    parser.add_argument('-d', '--days', type=int, metavar='NUMBER',
                        help=('Define log collection period in days.'
                              ' Timmy will collect only logs updated on or'
                              ' more recently then today minus the given'
                              ' number of days. Default - 30.'))
    parser.add_argument('-G', '--get', action='append', metavar='PATH',
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
    parser.add_argument('--one-way', action='store_true',
                        help=('When executing scripts_all_pairs (if defined),'
                              ' for each pair of nodes [A, B] run client'
                              ' script only on A (A->B connection).'
                              ' Default is to run both A->B and B->A.'))
    parser.add_argument('--max-pairs', type=int, metavar='NUMBER',
                        help=('When executing scripts_all_pairs (if defined),'
                              ' limit the amount of pairs processed'
                              ' simultaneously. Default is to run max number'
                              ' of pairs possible, which is num. nodes / 2.'))
    parser.add_argument('-P', '--put', nargs=2, action='append',
                        metavar=('SOURCE', 'DESTINATION'),
                        help=('Enables shell mode. Can be specified multiple'
                              ' times. Upload filemask via"scp -r" to node(s).'
                              ' Each argument must contain two strings -'
                              ' source file/path/mask and dest. file/path.'
                              ' For help on shell mode, read timmy/conf.py.'))
    parser.add_argument('-L', '--get-logs', nargs=3, action='append',
                        metavar=('PATH', 'INCLUDE', 'EXCLUDE'),
                        help=('Define specific logs to collect. Implies "-l".'
                              ' Each -L option requires 3 values in the'
                              ' following order: path, include, exclude.'
                              ' See configuration doc for details on each of'
                              ' these parameters. Values except path can be'
                              ' skipped by passing empty strings. Example: -L'
                              ' "/var/mylogs/" "" "exclude-string"'))
    parser.add_argument('--rqfile', metavar='PATH', action='append',
                        help=('Can be specified multiple times. Path to'
                              ' rqfile(s) in yaml format, overrides default.'))
    parser.add_argument('-l', '--logs', action='store_true',
                        help=('Collect logs from nodes. Logs are not collected'
                              ' by default due to their size.'))
    parser.add_argument('--logs-no-default', action='store_true',
                        help=('Do not use default log collection parameters,'
                              ' only use what has been provided either via -L'
                              ' or in rqfile(s). Implies "-l".'))
    parser.add_argument('--logs-speed', type=int, metavar='MBIT/S',
                        help=('Limit log collection bandwidth to 90%% of the'
                              ' specified speed in Mbit/s.'))
    parser.add_argument('--logs-speed-auto', action='store_true',
                        help=('Limit log collection bandwidth to 90%% of local'
                              ' admin interface speed. If speed detection'
                              ' fails, a default value will be used. See'
                              ' "logs_speed_default" in conf.py.'))
    parser.add_argument('--logs-coeff', type=float, metavar='RATIO',
                        help=('Estimated logs compression ratio - this value'
                              ' is used during free space check. Set to a'
                              ' lower value (default - 1.05) to collect logs'
                              ' of a total size larger than locally available'
                              '. Values lower than 0.3 are not recommended'
                              ' and may result in filling up local disk.'))
    parser.add_argument('--only-logs',
                        action='store_true',
                        help=('Only collect logs, do not run commands or'
                              ' collect files.'))
    parser.add_argument('--fake',
                        help='Do not run commands and scripts',
                        action='store_true')
    parser.add_argument('--fake-logs',
                        help='Do not collect logs, only calculate size.',
                        action='store_true')
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
                              ' This option disables any -v parameters.'),
                        action='store_true')
    parser.add_argument('--maxthreads', type=int, metavar='NUMBER',
                        help=('Maximum simultaneous nodes for command'
                              'execution.'))
    parser.add_argument('--logs-maxthreads', type=int, metavar='NUMBER',
                        help='Maximum simultaneous nodes for log collection.')
    parser.add_argument('-t', '--outputs-timestamp',
                        help=('Add timestamp to outputs - allows accumulating'
                              ' outputs of identical commands/scripts across'
                              ' runs. Only makes sense with --no-clean for'
                              ' subsequent runs.'),
                        action='store_true')
    parser.add_argument('-T', '--dir-timestamp',
                        help=('Add timestamp to output folders (defined by'
                              ' "outdir" and "archive_dir" config options).'
                              ' Makes each run store results in new folders.'
                              ' This way Timmy will always preserve previous'
                              ' results. Do not forget to clean up the results'
                              ' manually when using this option.'),
                        action='store_true')
    parser.add_argument('-m', '--module', metavar='INVENTORY MODULE',
                        default='fuel',
                        help='Use module to get node data')
    parser.add_argument('-a', '--analyze', action='store_true',
                        help=('Analyze collected outputs to determine node or'
                              'service health and print results'))
    parser.add_argument('--offline', action='store_true',
                        help=('Mark all nodes as offline, do not perform any'
                              'operations on the nodes'))
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help=('This works for -vvvv, -vvv, -vv, -v, -v -v,'
                              'etc, If no -v then logging.WARNING is '
                              'selected if more -v are provided it will '
                              'step to INFO and DEBUG unless the option '
                              '-q(--quiet) is specified'))
    return parser


@signal_wrapper
def main(argv=None):
    if argv is None:
        argv = sys.argv
    parser = parser_init()
    args, unknown = parser.parse_known_args(argv[1:])
    parser = parser_init(add_help=True)
    if args.module:
        inventory = __import__('timmy.modules.%s' % args.module,
                               fromlist=['timmy.modules'])
        parser = add_args(parser, inventory)
    args = parser.parse_args(argv[1:])
    if args.version:
        print(version)
        sys.exit(0)
    loglevels = [logging.WARNING, logging.INFO, logging.DEBUG]
    if args.quiet and not args.log_file:
        args.verbose = 0
    loglevel = loglevels[min(len(loglevels)-1, args.verbose)]
    # always enable debug log if log file specificed
    if args.log_file:
        loglevel = logging.DEBUG
        log_handler = logging.handlers.WatchedFileHandler(args.log_file)
    else:
        log_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(module)s: '
                                  '%(funcName)s(): %(message)s')
    log_handler.setFormatter(formatter)
    logger = logging.getLogger(project_name)
    logger.addHandler(log_handler)
    logger.setLevel(loglevel)
    conf = inventory.NodeManager.load_conf(args.config)
    inventory.check_args(args, conf)
    if args.put or args.command or args.script or args.get:
        conf['shell_mode'] = True
        conf['do_print_results'] = True
    if args.no_clean:
        conf['clean'] = False
    if args.maxthreads:
        conf['maxthreads'] = args.maxthreads
    if args.logs_maxthreads:
        conf['logs_maxthreads'] = args.logs_maxthreads
    if args.rqfile:
        conf['rqfile'] = []
        for file in args.rqfile:
            conf['rqfile'].append({'file': file, 'default': False})
    if args.days:
        conf['logs_days'] = args.days
    if args.logs_no_default:
        conf['logs_no_default'] = True
        args.logs = True
    if args.logs_speed or args.logs_speed_auto:
        conf['logs_speed_limit'] = True
    if args.logs_speed:
        conf['logs_speed'] = abs(args.logs_speed)
    if args.logs_coeff:
        conf['logs_size_coefficient'] = args.logs_coeff
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
    if args.get_logs:
        # this code should be after 'shell_mode' which cleans logs too
        args.logs = True
        for logs in args.get_logs:
            logs_conf = {}
            logs_conf['path'] = logs[0]
            if logs[1]:
                logs_conf['include'] = [logs[1]]
            if logs[2]:
                logs_conf['exclude'] = [logs[2]]
            if args.days:
                logs_conf['start'] = args.days
            conf['logs'].append(logs_conf)
    if args.role:
        filter['roles'] = args.role
    if args.env is not None:
        filter['cluster'] = [args.env]
    if args.id:
        filter['id'] = args.id
    if args.outputs_timestamp:
        conf['outputs_timestamp'] = True
    if args.dir_timestamp:
        conf['dir_timestamp'] = True
    if args.dest_file:
        conf['archive_dir'] = os.path.split(args.dest_file)[0]
        if not conf['archive_dir']:
            # this is mainly to see the path in logs instad of ""
            conf['archive_dir'] = os.getcwd()
        conf['archive_name'] = os.path.split(args.dest_file)[1]
    if args.analyze:
        conf['analyze'] = True
    if args.offline:
        conf['offline'] = True
    if args.one_way:
        conf['scripts_all_pairs_one_way'] = True
    if args.max_pairs:
        conf['scripts_all_pairs_max_pairs'] = args.max_pairs
    logger.info('Using rqdir: %s, rqfile: %s' %
                (conf['rqdir'], conf['rqfile']))
    nm = pretty_run(args.quiet, 'Initializing node data',
                    inventory.NodeManager,
                    kwargs={'conf': conf,
                            'nodes_json': args.nodes_json})
    logs = False
    if not conf['offline'] and (args.only_logs or args.logs):
        logs = True
        size = pretty_run(args.quiet, 'Calculating logs size',
                          nm.calculate_log_size)
        if size == 0:
            logger.warning('Size zero - no logs to collect.')
            has_logs = False
        else:
            has_logs = True
            print(('Total logs size to collect before compression: %dMB.\n'
                   'Compressed logs will take less space.') % (size/1048576))
            print('Log collection period: %s days.' % conf['logs_days'])
            enough_space = pretty_run(args.quiet, 'Checking free space',
                                      nm.is_enough_space)
            if not enough_space:
                logger.error('Not enough space for logs in "%s", exiting.' %
                             nm.conf['archive_dir'])
                sys.exit(100)
    if not conf['offline'] and not args.only_logs:
        if nm.has(Node.pkey):
            pretty_run(args.quiet, 'Uploading files', nm.put_files)
        if nm.has(Node.ckey, Node.skey):
            pretty_run(args.quiet, 'Executing commands and scripts',
                       nm.run_commands, kwargs={'fake': args.fake})
    if conf['analyze']:
        pretty_run(args.quiet, 'Analyzing outputs', analyze, args=[nm])
    if not conf['offline'] and not args.only_logs:
        if nm.has('scripts_all_pairs'):
            pretty_run(args.quiet, 'Executing paired scripts',
                       nm.run_scripts_all_pairs)
        if nm.has(Node.fkey, Node.flkey):
            pretty_run(args.quiet, 'Collecting files and filelists',
                       nm.get_files)
        if not args.no_archive and nm.has(*Node.conf_archive_general):
            pretty_run(args.quiet, 'Creating outputs and files archive',
                       nm.create_archive_general, args=(60,))
    if logs and has_logs and enough_space:
        msg = 'Collecting and packing logs'
        pretty_run(args.quiet, msg, nm.get_logs,
                   args=(conf['compress_timeout'],),
                   kwargs={'fake': args.fake_logs})
    logger.info("Nodes:\n%s" % nm)
    if not args.quiet:
        print('Run complete. Node information:')
        print(nm)
    if conf['do_print_results']:
        if nm.has(Node.ckey, Node.skey):
            if not args.quiet:
                print('Results:')
            output_dict = {}
            maxlength = 0
            for node in nm.nodes.values():
                name, output = node.get_results(node.mapcmds)
                output_dict[node.ip] = {'name': name, 'output': output}
                name, output2 = node.get_results(node.mapscr)
                output_dict[node.ip]['output'] += output2
                maxlength = len(name) if len(name) > maxlength else maxlength
            for node in nm.sorted_nodes():
                for line in output_dict[node.ip]['output']:
                    name = output_dict[node.ip]['name'].rjust(maxlength)
                    print("%s: %s" % (name, line))
    if conf['analyze']:
        analyze_print_results(nm)
    if all([nm.has(Node.ckey, Node.skey, Node.fkey, Node.flkey),
            not args.quiet, not conf['offline']]):
        print('Outputs and/or files available in "%s".' % nm.conf['outdir'])
    if all([not args.no_archive, nm.has(*Node.conf_archive_general),
            not args.quiet, not conf['offline']]):
        print('Archives available in "%s".' % nm.conf['archive_dir'])


if __name__ == '__main__':
    sys.exit(main(sys.argv))
