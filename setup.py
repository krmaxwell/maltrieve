#!/usr/bin/env python
from distutils.core import setup

setup(name='maltrieve',
      version='0.6',
      description="A tool to retrieve malware directly from the source for security researchers.",
      author='Kyle Maxwell',
      author_email='krmaxwell@gmail.com',
      url='https://github.com/krmaxwell/maltrieve',
      package_dir={'maltrieve': 'src'},
      packages=['maltrieve'])
