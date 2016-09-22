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


import unittest
from timmy import conf


class ConfTest(unittest.TestCase):
    def test_param_presence_and_types(self):
        type_error = 'config key %s has incorrect type %s, should be %s'
        param_types = {
            'hard_filter': dict,
            'soft_filter': dict,
            'ssh_opts': list,
            'env_vars': list,
            'timeout': int,
            'prefix': str,
            'rqdir': str,
            'rqfile': list,
            'compress_timeout': int,
            'outdir': str,
            'archive_dir': str,
            'archive_name': str,
            'outputs_timestamp': bool,
            'dir_timestamp': bool,
            'put': list,
            'cmds': list,
            'scripts': list,
            'files': list,
            'filelists': list,
            'logs': list,
            'logs_no_default': bool,
            'logs_days': int,
            'logs_speed_limit': bool,
            'logs_speed_default': int,
            'logs_speed': int,
            'logs_size_coefficient': float,
            'shell_mode': bool,
            'do_print_results': bool,
            'clean': bool
        }
        config = conf.init_default_conf()
        for key in param_types:
            self.assertEqual(type(config[key]), param_types[key],
                             type_error % (key, type(config[key]),
                                           param_types[key]))


if __name__ == '__main__':
    unittest.main()
