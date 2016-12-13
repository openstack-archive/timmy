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

'''
please import and use health constants from analyze_health
GREEN - no issues
UNKNOWN - cannot determine / cannot parse output
YELLOW - condition is bad but not critical / impactful
RED - critical / impactful condition


if you want to write log messages, add the following lines:
from timmy.env import project_name
import logging


logger = logging.getLogger(project_name)
'''
from timmy.analyze_health import GREEN, UNKNOWN, YELLOW, RED
from timmy.env import project_name
import logging


logger = logging.getLogger(project_name)


def register(function_mapping):
    '''
    this function is mandatory and it's name must be "register"
    it should have 1 argument which is a dict
    it should update the dict with a relation between script names and
        analyzing functions
    more than one script can be mapped by a single module
    see script names in timmy_data/rq/scripts folder
    '''
    function_mapping['script-basename'] = parsing_function


def parsing_function(data, script, node):
    '''
    each analyzing function should have 3 arguments:
    data - list of strings aquired by reading the output file
    script - path to the script file
    node - node object

    return should contain 2 values:
    health - set to one of the imported constants according to the analysis
    details - a list of strings - an explanatory message or
        lines which were indicative of the issue
    '''
    health = UNKNOWN
    line = data[0]  # in this example we only look at the first line
    details = [line]
    if line.find('error'):
        health = RED
        details.append('This is very bad! Do something NOW!!!')
    elif line.find('warning'):
        health = YELLOW
        details.append('Who cares if it is not RED, right? :)')
    elif line.find('ok'):
        health = GREEN
    return health, details
