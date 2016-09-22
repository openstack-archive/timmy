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
    def test_filelists_and_scripts(self):
        def check_sep(val, err_text, err_text2):
            self.assertEqual(os.path.sep in val, False,
                             err_text % (err_text2, val, err_text2))

        def iter_dict(d, err_text, err_text2):
            for el in d.values():
                if type(el) is dict:
                    # for sub-matches
                    iter_dict(el, err_text, err_text2)
                elif type(el) is str:
                    # single value, not a list
                    self.assertEqual(os.path.sep in el, False, sep_error % el)
                else:
                    for sub in el:
                        # list of values
                        if type(sub) is dict:
                            # for scripts with env. variables
                            for k in sub.keys():
                                check_sep(k, err_text, err_text2)
                        else:
                            # normal list of strings
                            check_sep(sub, err_text, err_text2)

        sep_error = ('default %s value %s has path separator(s) - this '
                     'will cause NodeManager to search the file by full path '
                     'instead of looking in the default rq/%s path.')
        config = conf.init_default_conf()
        for rqfile in config['rqfile']:
            f = rqfile['file']
            if os.path.sep in f:
                src = tools.load_yaml_file(f)
            else:
                f = os.path.join(self.rqdir, f)
                src = tools.load_yaml_file(f)
            iter_dict(src['filelists'], sep_error, 'filelists')
            iter_dict(src['scripts'], sep_error, 'scripts')


if __name__ == '__main__':
    unittest.main()
