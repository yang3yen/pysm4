#!/usr/bin/env python


import sys
import pysm4

from setuptools import setup
from setuptools.command.test import test as test_command


class PyTest(test_command):
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        test_command.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


url = 'https://github.com/yang3yen/pysm4.git'
with open('README.md', 'r', encoding='utf-8') as fp:
    long_description = fp.read()

setup(name=pysm4.__title__,
      version=pysm4.__version__,
      author=pysm4.__author__,
      author_email=pysm4.__email__,
      license=pysm4.__license__,
      url=url,
      description='Python SM4',
      long_description=long_description,
      long_description_content_type="text/markdown",
      platforms='any',
      zip_safe=False,
      packages=['pysm4'],
      classifiers=[
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11'
      ],
      cmdclass={'test': PyTest},
      tests_require=['pytest>=2.8.0']
      )
