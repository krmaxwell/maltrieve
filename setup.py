#!/usr/bin/env python
from distutils.core import setup

setup(name = 'maltrieve',
    version = '1.0.0',
    description = "A tool to retrieve malware directly from the source for security researchers.",
    author = 'Kyle Maxwell',
    author_email = 'krmaxwell@gmail.com',
    url = 'https://github.com/technoskald/maltrieve',
    package_dir = {'maltrieve': 'src'},
    packages = ['maltrieve'],
)
