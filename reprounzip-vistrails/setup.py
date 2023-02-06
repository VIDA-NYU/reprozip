import io
import os
from setuptools import setup
import sys


# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))


# Need to specify encoding for PY3, which has the worst unicode handling ever
with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
req = [
    'reprounzip>=1.0.0',
    'rpaths>=0.8']
if sys.version_info < (2, 7):
    req.append('argparse')
setup(name='reprounzip-vistrails',
      version='1.2',
      packages=['reprounzip', 'reprounzip.plugins'],
      entry_points={
          'reprounzip.plugins': [
              'vistrails = reprounzip.plugins.vistrails:setup_vistrails']},
      namespace_packages=['reprounzip', 'reprounzip.plugins'],
      install_requires=req,
      description="Integrates the ReproZip unpacker with the VisTrails "
                  "workflow management system",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='reprozip@nyu.edu',
      maintainer="Remi Rampin",
      maintainer_email='remi@rampin.org',
      url='https://www.reprozip.org/',
      project_urls={
          'Documentation': 'https://docs.reprozip.org/',
          'Examples': 'https://examples.reprozip.org/',
          'Source': 'https://github.com/VIDA-NYU/reprozip',
          'Bug Tracker': 'https://github.com/VIDA-NYU/reprozip/issues',
          'Chat': 'https://riot.im/app/#/room/#reprozip:matrix.org',
          'Changelog':
              'https://github.com/VIDA-NYU/reprozip/blob/1.x/CHANGELOG.md',
      },
      long_description=description,
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu', 'vistrails'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
