#!/usr/bin/env python
from distutils.core import setup
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt')
reqs = [str(ir.req) for ir in install_reqs]

setup(name='maltrieve',
      version='0.6',
      description="A tool to retrieve malware directly from the source for security researchers.",
      author='Kyle Maxwell',
      author_email='krmaxwell@gmail.com',
      url='http://maltrieve.org',
      install_requires=reqs,
      package_dir={'maltrieve': 'src'},
      packages=['maltrieve'],
      entry_points={'console_scripts': ['maltrieve =  maltrieve:main']})
