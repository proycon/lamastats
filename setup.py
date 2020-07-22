#! /usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
from setuptools import setup


try:
    os.chdir(os.path.dirname(sys.argv[0]))
except:
    pass


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "lamastats",
    version = "0.2.0",
    author = "Maarten van Gompel",
    author_email = "proycon@anaproy.nl",
    description = ("Simple visitor analytics application for presenting usage statistics on several components included in LaMachine."),
    license = "GPL",
    keywords = "analytics",
    url = "https://github.com/proycon/lamastats",
    packages=['lamastats'],
    long_description=read('README.rst'),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Text Processing :: Linguistic",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Operating System :: POSIX",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    entry_points = {
        'console_scripts': [
            'lamastats = lamastats.lamastats:main'
        ]
    },
    package_data = {'lamastats':['GeoIP.dat'] },
    install_requires=['pygeoip', 'apache_log_parser']
)
