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
import re
import yaml


logger = logging.getLogger(project_name)


def register(function_mapping):
    function_mapping['rabbitmqctl-list-queues'] = parse_list_queues
    function_mapping['rabbitmqctl-status'] = parse_status


def parse_list_queues(data, script, node):
    warning = 100
    error = 1000
    health = GREEN
    details = []
    for line in data[1:]:
        elements = line.rstrip().split()
        if len(elements) < 2:
            logger.warning('no value in list_queues: "%s"' % line.rstrip())
        else:
            count = int(elements[1])
            if count < error and count >= warning:
                health = max(health, YELLOW)
                details.append(line)
    return health, details


def prepare_status(data):
    bad_yaml = ''.join(data[1:])
    # quoting string elements
    bad_yaml = re.sub(r'([,{])([a-z_A-Z]+)([,}])', r'\1"\2"\3', bad_yaml)
    # changing first element int a key - replacing , with :
    bad_yaml = re.sub(r'({[^,]+),', r'\1:', bad_yaml)
    bad_yaml_list = list(bad_yaml)
    good_yaml, _ = fix_dicts(bad_yaml_list, 0)
    status_list = yaml.load(''.join(good_yaml))
    status_dict = squash_dicts(status_list)
    return status_dict


def fix_dicts(json_str_list, pos):
    '''recursively puts all comma-separted values into square
    brackets to make data look like normal 'key: value' dicts
    '''
    quoted_string = False
    value = True
    value_pos = 0
    commas = False
    is_list = False
    in_list = 0
    while pos < len(json_str_list):
        if not quoted_string:
            if json_str_list[pos] == '{':
                json_str_list, pos = fix_dicts(json_str_list, pos+1)
            elif json_str_list[pos] == '"':
                quoted_string = True
            elif json_str_list[pos] == ':':
                value = True
                value_pos = pos + 1
            elif json_str_list[pos] == '[':
                if value and not commas:
                    is_list = True
                    in_list += 1
            elif json_str_list[pos] == ']':
                in_list -= 1
            elif json_str_list[pos] == ',':
                commas = True
                if not in_list:
                    is_list = False
            elif json_str_list[pos] == '}':
                if not is_list and commas:
                    json_str_list = (json_str_list[:value_pos] + ['['] +
                                     json_str_list[value_pos:pos] + [']'] +
                                     json_str_list[pos:])
                pos += 2
                return json_str_list, pos
        elif json_str_list[pos] == '"':
            quoted_string = False
        pos += 1
    return json_str_list, pos


def squash_dicts(input_data):
    # recursively converts [{a:1},{b:2},{c:3}...] into {a:1, b:2, c:3}'''
    if type(input_data) is list:
        for i in range(len(input_data)):
            input_data[i] = squash_dicts(input_data[i])
        if all([type(i) is dict for i in input_data]):
            kv_list = [(k, v) for i in input_data for k, v in i.items()]
            input_data = dict(kv_list)
    elif type(input_data) is dict:
        for k, v in input_data.items():
            input_data[k] = squash_dicts(v)
    return input_data


def parse_status(data, script, node):
    status = prepare_status(data)
    health = GREEN
    details = []

    # disk free check
    try:
        dfree = int(status['disk_free'])
        dlimit = int(status['disk_free_limit'])
        dfree_ok = 10**9  # 1GB
        if dfree > dlimit and dfree < dfree_ok:
            health = max(health, YELLOW)
            details.append('disk_free: %s, disk_free_limit: %s'
                           % (dfree, dlimit))
        elif dfree <= dlimit:
            health = max(health, RED)
            details.append('disk_free: %s, disk_free_limit: %s'
                           % (dfree, dlimit))
    except ValueError:
        details.append('cannot convert disk_free* to int')
        health = max(health, UNKNOWN)
    except KeyError:
        details.append('disk_free* not present')
        health = max(health, UNKNOWN)

    # process limit check
    try:
        pused = float(status['processes']['used'])
        plimit = float(status['processes']['limit'])
        ok_ratio = 0.9
        if pused < plimit and pused/plimit > ok_ratio:
            health = max(health, YELLOW)
            details.append('processes used: %s, processes limit: %s'
                           % (pused, plimit))
        elif pused >= plimit:
            health = max(health, RED)
            details.append('processes used: %s, processes limit: %s'
                           % (pused, plimit))
    except ValueError:
        details.append('cannot convert processes* to numbers')
        health = max(health, UNKNOWN)
    except KeyError:
        details.append('processes* not present')
        health = max(health, UNKNOWN)

    # fd check
    try:
        sused = float(status['file_descriptors']['sockets_used'])
        slimit = float(status['file_descriptors']['sockets_limit'])
        ok_ratio = 0.9
        if sused < slimit and sused/slimit > ok_ratio:
            health = max(health, YELLOW)
            details.append('sockets used: %s, sockets limit: %s'
                           % (sused, slimit))
        elif sused >= slimit:
            health = max(health, RED)
            details.append('sockets used: %s, sockets limit: %s'
                           % (sused, slimit))
        fdused = float(status['file_descriptors']['total_used'])
        fdlimit = float(status['file_descriptors']['total_limit'])
        ok_ratio = 0.9
        if fdused < fdlimit and fdused/fdlimit > ok_ratio:
            health = max(health, YELLOW)
            details.append('fd total used: %s, fd total limit: %s'
                           % (fdused, fdlimit))
        elif fdused >= fdlimit:
            health = max(health, RED)
            details.append('fd total used: %s, fd total limit: %s'
                           % (fdused, fdlimit))
    except ValueError:
        details.append('cannot convert file_descriptors* to numbers')
        health = max(health, UNKNOWN)
    except KeyError:
        details.append('file_descriptors* not present')
        health = max(health, UNKNOWN)

    return health, details
