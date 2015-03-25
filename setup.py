#!/usr/bin/env python
from distutils.core import setup

setup(name='maltrieve',
      version='0.6',
      description="A tool to retrieve malware directly from the source for security researchers.",
      author='Kyle Maxwell',
      author_email='krmaxwell@gmail.com',
      url='http://maltrieve.org',
      install_requires=[
          'argparse==1.2.1',
          'beautifulsoup4==4.3.2',
          'feedparser==5.1.3',
          'gevent==1.0.1',
          'greenlet==0.4.2',
          'grequests==0.2.0',
          'python-magic==0.4.6',
          'requests==2.3.0',
          'wsgiref==0.1.2',
          'pre-commit',
          'pytest'
      ],
      package_dir={'maltrieve': 'src'},
      packages=['maltrieve'],
      entry_points={'console_scripts': ['maltrieve =  maltrieve:main']})
