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
import loadconf


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
    parser.add_argument('-f', '--nodes',
                        help='nodes file', default='nodes.json')
    parser.add_argument('-e', '--extended', action='store_true',
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
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
    conf = loadconf.load_conf(args.config)
    n = nodes.Nodes(conf=conf,
                    extended=args.extended,
                    cluster=args.cluster,
                    destdir=args.dest_file)
    # nodes.print_nodes()
    n.get_node_file_list()
    n.launch_ssh(conf['out-dir'])
    n.get_conf_files(conf['out-dir'])
    n.create_archive_general(conf['out-dir'], '/tmp/timmy-gen.tar.bz2', 60)
    n.print_nodes()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
