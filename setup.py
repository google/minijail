#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A file that specifies how to install minijail's python-based tool(s)."""

import os
from setuptools import setup


this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='minijail',
      version='0.12',
      description='A set of tools for Minijail',
      classifiers=[
          'Programming Language :: Python :: 3',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: Linux',
      ],
      python_requires='>=3.6',
      license='Apache License 2.0',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Minijail Developers',
      author_email='minijail-dev@google.com',
      url='https://google.github.io/minijail/',
      packages=['minijail'],
      package_dir={'minijail': 'tools'},
      entry_points={
          'console_scripts': [
              'compile_seccomp_policy = minijail.compile_seccomp_policy:main',
              'generate_seccomp_policy = minijail.generate_seccomp_policy:main',
              'generate_constants_json = minijail.generate_constants_json:main',
          ],
      },
)
