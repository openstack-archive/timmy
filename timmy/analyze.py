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

from timmy.env import project_name
import logging
import sys


logger = logging.getLogger(project_name)


def analyze(node_manager):
    col_msg = 'Column "%s" not found in output of "%s" from node "%s"'
    green = 0
    unknown = 1
    yellow = 2
    red = 3

    def parse_df_m(data, script, node):
        column_use = "Use%"
        full = 100
        near_full = 80
        health = green
        details = []
        if column_use not in data[0]:
            logger.warning(col_msg % (column_use, script, node.repr))
            health = unknown
        index = data[0].split().index(column_use)
        for line in data[2:]:
            value = int(line.split()[index][:-1])
            if value >= full:
                health = red
                details.append(line)
            elif value >= near_full:
                health = yellow if health < yellow else health
                details.append(line)
        return health, details

    def parse_df_i(data, script, node):
        column_use = "IUse%"
        full = 100
        near_full = 80
        health = green
        details = []
        if column_use not in data[0]:
            logger.warning(col_msg % (column_use, script, node.repr))
            health = unknown
        index = data[0].split().index(column_use)
        for line in data[2:]:
            if "%" in line.split()[index]:
                value = int(line.split()[index][:-1])
                if value >= full:
                    health = red
                    details.append(line)
                elif value >= near_full:
                    health = yellow if health < yellow else health
                    details.append(line)
        return health, details

    fn_mapping = {"df-m": parse_df_m,
                  "df-i": parse_df_i}
    results = {}
    for node in node_manager.nodes.values():
        for script, output_file in node.mapscr.items():
            if script in fn_mapping:
                with open(output_file, "r") as f:
                    data = [l.rstrip() for l in f.readlines()]
                health, details = fn_mapping[script](data, script, node)
                if node.repr not in results:
                    results[node.repr] = []
                results[node.repr].append({"script": script,
                                           "output_file": output_file,
                                           "health": health,
                                           "details": details})
    node_manager.analyze_results = results


def analyze_print_results(node_manager):
    code_colors = {3: ["RED", "\033[91m"],
                   2: ["YELLOW", "\033[93m"],
                   0: ["GREEN", "\033[92m"],
                   1: ["BLUE", "\033[94m"]}
    color_end = "\033[0m"
    print("Nodes health analysis:")
    for node, result in node_manager.analyze_results.items():
        node_health = max([x["health"] for x in result])
        node_color = code_colors[node_health][1]
        health_repr = code_colors[node_health][0]
        print("    %s%s: %s%s" % (node_color, node, health_repr, color_end))
        if node_health == 0:
            continue
        for r in result:
            if r['health'] == 0:
                continue
            color = code_colors[r["health"]][1]
            sys.stdout.write(color)
            for key, value in r.items():
                if key == "health":
                    value = code_colors[value][0]
                if key == "details" and len(value) > 0:
                    if len(value) > 1:
                        print("        details:")
                        for d in value:
                            print("            - %s" % d)
                    else:
                        print("        details: %s" % value[0])
                elif key != "details":
                    print("        %s: %s" % (key, value))
            sys.stdout.write(color_end)
