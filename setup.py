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


from setuptools import setup
import os
from timmy.env import project_name, version

pname = project_name
dtm = os.path.join(os.path.abspath(os.sep), 'usr', 'share', pname)
rqfiles = [(os.path.join(dtm, root), [os.path.join(root, f) for f in files])
           for root, dirs, files in os.walk('rq')]
rqfiles.append((os.path.join(dtm, 'configs'), ['config.yaml', 'rq.yaml']))
package_data = True

if os.environ.get("READTHEDOCS", False):
    rqfiles = None
    package_data = False


setup(name=pname,
      version=version,
      author="Aleksandr Dobdin",
      author_email='dobdin@gmail.com',
      license='Apache2',
      url='https://github.com/adobdin/timmy',
      description = ('Mirantis OpenStack Ansible-like tool for parallel node '
                     'operations: two-way data transfer, log collection, '
                     'remote command execution'),
      long_description=open('README.md').read(),
      packages=[pname],
      install_requires=['pyyaml'],
      data_files=rqfiles,
      include_package_data=package_data,
      entry_points={'console_scripts': ['%s=%s.cli:main' % (pname, pname)]},
      )
