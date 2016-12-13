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

from timmy.analyze_health import GREEN, UNKNOWN, YELLOW, RED
from timmy.env import project_name
import imp
import logging
import os
import sys


logger = logging.getLogger(project_name)


def analyze(node_manager):
    def is_module(f):
        return f.endswith('.py') and not f.startswith('__')

    fn_mapping = {}
    modules_dir = 'analyze_modules'
    modules_path = os.path.join(os.path.dirname(__file__), modules_dir)
    module_paths = m = []
    for item in os.walk(modules_path):
        m.extend([os.sep.join([item[0], f]) for f in item[2] if is_module(f)])
    for module_path in module_paths:
        module_name = os.path.basename(module_path)
        module = imp.load_source(module_name, module_path)
        module.register(fn_mapping)

    results = {}
    for node in node_manager.nodes.values():
        if not node.mapscr:
            node.generate_mapscr()
        for script, param in node.mapscr.items():
            if script in fn_mapping:
                if not os.path.exists(param['output_path']):
                    logger.warning('File %s does not exist'
                                   % param['output_path'])
                    continue
                with open(param['output_path'], 'r') as f:
                    data = [l.rstrip() for l in f.readlines()]
                health, details = fn_mapping[script](data, script, node)
                if node.repr not in results:
                    results[node.repr] = []
                results[node.repr].append({'script': script,
                                           'output_file': param['output_path'],
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
    for node, result in node_manager.analyze_results.items():
        node_health = max([x['health'] for x in result])
        node_color = code_colors[node_health][1]
        health_repr = code_colors[node_health][0]
        print('    %s%s: %s%s' % (node_color, node, health_repr, color_end))
        if node_health == 0:
            continue
        for r in result:
            if r['health'] == 0:
                continue
            color = code_colors[r['health']][1]
            sys.stdout.write(color)
            health_repr = code_colors[r['health']][0]
            print('        %s: %s' % (r['script'], health_repr))
            print('            %s: %s' % ('output_file', r['output_file']))
            if len(r['details']) > 1:
                print('            details:')
                for d in r['details']:
                    print('                - %s' % d)
            else:
                print('            details: %s' % r['details'][0])
            sys.stdout.write(color_end)
