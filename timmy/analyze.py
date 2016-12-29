#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#    Copyright 2016 Mirantis, Inc.
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

import logging
import os
import sys
import timmy
from timmy.analyze_health import GREEN, UNKNOWN, YELLOW, RED
from timmy.env import project_name


logger = logging.getLogger(project_name)


def analyze(node_manager):
    def is_module(f):
        return f.endswith('.py') and not f.startswith('__')

    fn_mapping = {}
    modules_dir = 'analyze_modules'
    scan_path = os.path.join(os.path.dirname(__file__), modules_dir)
    base_path = os.path.split(timmy.__path__[0])[0]
    for item in os.walk(scan_path):
        for module_path in [m for m in item[2] if is_module(m)]:
            module_full_path = os.path.join(scan_path, module_path)
            module_rel_path = os.path.relpath(module_full_path, base_path)
            module_rel_path_noext = os.path.splitext(module_rel_path)[0]
            module_name = module_rel_path_noext.replace(os.path.sep, '.')
            module = __import__(module_name, fromlist=[project_name])
            module.register(fn_mapping)

    results = {}
    for node in node_manager.sorted_nodes():
        if not node.mapscr:
            node.generate_mapscr()
        for script, param in node.mapscr.items():
            if script in fn_mapping:
                if not os.path.exists(param['output_path']):
                    logger.warning('File %s does not exist'
                                   % param['output_path'])
                    continue
                try:
                    with open(param['output_path'], 'r') as f:
                        stdout = f.read()
                    if os.path.exists(param['stderr_path']):
                        with open(param['stderr_path'], 'r') as f:
                            stderr = f.read()
                            try:
                                exitcode = stderr.splitlines()[0]
                                exitcode = int(exitcode.rstrip().split()[1])
                            except IndexError:
                                logger.warning('Could not extract exitcode'
                                               ' from file "%s"' %
                                               param['stderr_path'])
                            except ValueError:
                                logger.warning('Could not convert exitcode'
                                               ' in file "%s" to int' %
                                               param['stderr_path'])
                    else:
                        stderr = None
                        exitcode = 0
                except IOError as e:
                    logger.warning('Could not read from %s' % e.filename)
                health, details = fn_mapping[script](stdout, script, node,
                                                     stderr=stderr,
                                                     exitcode=exitcode)
                if node.repr not in results:
                    results[node.repr] = []
                results[node.repr].append({'script': script,
                                           'output_file': param['output_path'],
                                           'stderr_file': param['stderr_path'],
                                           'exitcode': exitcode,
                                           'health': health,
                                           'details': details})
    node_manager.analyze_results = results


def analyze_print_results(node_manager):
    code_colors = {GREEN: ['GREEN', '\033[92m'],
                   UNKNOWN: ['UNKNOWN', '\033[94m'],
                   YELLOW: ['YELLOW', '\033[93m'],
                   RED: ['RED', '\033[91m']}
    color_end = '\033[0m'
    print('Nodes health analysis:')
    ag = True
    for node, result in sorted(node_manager.analyze_results.items()):
        node_health = max([x['health'] for x in result])
        node_color = code_colors[node_health][1]
        health_repr = code_colors[node_health][0]
        if node_health == 0:
            continue
        ag = False
        print('    %s%s: %s%s' % (node_color, node, health_repr, color_end))
        for r in result:
            if r['health'] == 0:
                continue
            color = code_colors[r['health']][1]
            sys.stdout.write(color)
            health_repr = code_colors[r['health']][0]
            print('%s%s: %s' % (8*' ', r['script'], health_repr))
            print('%s%s: %s' % (12*' ', 'output_file', r['output_file']))
            if ((r['stderr_file'] is not None) and
                    (os.path.exists(r['stderr_file']))):
                print('%s%s: %s' % (12*' ', 'stderr_file', r['stderr_file']))
            if r['exitcode'] != 0:
                print('%s%s: %s' % (12*' ', 'exitcode', r['exitcode']))
            if len(r['details']) > 1:
                print('%sdetails:' % (12*' '))
                for d in r['details']:
                    print('%s- %s' % (16*' ', d))
            elif r['details']:
                print('%sdetails: %s' % (12*' ', r['details'][0]))
            sys.stdout.write(color_end)
    if ag:
        sys.stdout.write(code_colors[GREEN][1])
        print('All green')
        sys.stdout.write(color_end)
