#!/usr/bin/env python

from setuptools import setup

setup(name='timmy',
      version='0.1',
      author = "Aleksandr Dobdin",
      author_email = 'dobdin@gmail.com',
      license = 'Apache2',
      url = 'https://github.com/adobdin/timmy',
      #  long_description=read('README'),
      packages = ["timmy"],
      entry_points = {
          'console_scripts': ['timmy = timmy.cli:main']
      }
      )
