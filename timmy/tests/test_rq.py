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


import os
import unittest
from timmy import conf, tools


class RQDefault(unittest.TestCase):
    def test_filelists(self):
        def iter_dict(d):
            for el in d.values():
                if type(el) is dict:
                    iter_dict(el)
                elif type(el) is str:
                    self.assertEqual(os.path.sep in el, False, sep_error % el)
                else:
                    for sub in el:
                        self.assertEqual(os.path.sep in sub, False,
                                         sep_error % el)

        sep_error = ('default filelist value %s has path separator(s) - this '
                     'will cause NodeManager to search the file by full path '
                     'instead of looking in the default rq/filelists path.')
        config = conf.load_conf(None)
        for rqfile in config['rqfile']:
            f = rqfile['file']
            if os.path.sep in f:
                src = tools.load_yaml_file(f)
            else:
                f = os.path.join(self.rqdir, f)
                src = tools.load_yaml_file(f)
            filelists = src['filelists']
            iter_dict(filelists)


if __name__ == '__main__':
    unittest.main()
