#!/usr/bin/env python

from setuptools import setup
import os

pname = 'timmy'
dtm = os.path.join(os.path.abspath(os.sep), 'usr', 'share', pname)
rqfiles = [(os.path.join(dtm, root), [os.path.join(root, f) for f in files])
           for root, dirs, files in os.walk('rq')]
rqfiles.append((os.path.join(dtm, 'configs'), ['config.yaml', 'rq.yaml']))

setup(name=pname,
      version='1.2.0',
      author="Aleksandr Dobdin",
      author_email='dobdin@gmail.com',
      license='Apache2',
      url='https://github.com/adobdin/timmy',
      long_description=open('README.md').read(),
      packages=[pname],
      data_files=rqfiles,
      include_package_data=True,
      entry_points={'console_scripts': ['%s=%s.cli:main' %(pname, pname) ]},
      )
