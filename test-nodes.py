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

    parser = argparse.ArgumentParser(description='need to add description')
    parser.add_argument('--config', default='config.yaml',
                        help='Config file')
    parser.add_argument('-o', '--dest-file', default='/tmp/',
                        help='output archive file')
    parser.add_argument('-f', '--nodes',
                        help='nodes file', default='nodes.json')
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
    args.extended = args.extended == "1"
    conf = loadconf.load_conf(args.config)
    n = nodes.Nodes(conf=conf,
                    extended=args.extended,
                    cluster=args.cluster,
                    destdir=args.dest_file)
    # nodes.print_nodes()
    n.get_node_file_list()
    n.print_nodes()
    n.get_release()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
