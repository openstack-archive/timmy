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
import logging


logger = logging.getLogger(project_name)

col_msg = 'Column "%s" not found in output of "%s" from node "%s"'


def register(function_mapping):
    function_mapping['df-m'] = parse_df_m
    function_mapping['df-i'] = parse_df_i


def parse_df_m(data, script, node):
    column_use = "Use%"
    full = 100
    near_full = 80
    health = GREEN
    details = []
    if column_use not in data[0]:
        logger.warning(col_msg % (column_use, script, node.repr))
        health = UNKNOWN
    index = data[0].split().index(column_use)
    prepend_str = ''  # workaround for data which spans 2 lines
    index_shift = 0
    for line in data[2:]:
        if len(line.split()) <= index:
            prepend_str = line.rstrip()
            index_shift = len(line.split())
            continue
        value = int(line.split()[index - index_shift][:-1])
        if value >= full:
            health = RED
            details.append(prepend_str + line)
        elif value >= near_full:
            health = YELLOW if health < YELLOW else health
            details.append(prepend_str + line)
        prepend_str = ''
        index_shift = 0
    return health, details


def parse_df_i(data, script, node):
    column_use = "IUse%"
    full = 100
    near_full = 80
    health = GREEN
    details = []
    if column_use not in data[0]:
        logger.warning(col_msg % (column_use, script, node.repr))
        health = UNKNOWN
    index = data[0].split().index(column_use)
    prepend_str = ''  # workaround for data which spans 2 lines
    index_shift = 0
    for line in data[2:]:
        if len(line.split()) <= index:
            prepend_str = line.rstrip()
            index_shift = len(line.split())
            continue
        if "%" in line.split()[index - index_shift]:
            value = int(line.split()[index - index_shift][:-1])
            if value >= full:
                health = RED
                details.append(prepend_str + line)
            elif value >= near_full:
                health = YELLOW if health < YELLOW else health
                details.append(prepend_str + line)
        prepend_str = ''
    return health, details
