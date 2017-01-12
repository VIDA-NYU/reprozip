import io
import os
import platform
from setuptools import setup, Extension
import sys


# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))


# This won't build on non-Linux -- don't even try
if platform.system().lower() != 'linux':
    sys.stderr.write("reprozip uses ptrace and thus only works on Linux\n"
                     "You can however install reprounzip and plugins on other "
                     "platforms\n")
    sys.exit(1)


# List the source files
sources = ['pytracer.c', 'tracer.c', 'syscalls.c', 'database.c',
           'ptrace_utils.c', 'utils.c', 'log.c']
# They can be found under native/
sources = [os.path.join('native', n) for n in sources]


# Setup the libraries
libraries = ['sqlite3', 'rt']


# Build the C module
pytracer = Extension('reprozip._pytracer',
                     sources=sources,
                     libraries=libraries)

# Need to specify encoding for PY3, which has the worst unicode handling ever
with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
req = [
    'PyYAML',
    'rpaths>=0.8',
    'usagestats>=0.3',
    'requests']
setup(name='reprozip',
      version='1.1.0',
      ext_modules=[pytracer],
      packages=['reprozip', 'reprozip.tracer'],
      entry_points={
          'console_scripts': [
              'reprozip = reprozip.main:main'],
          'reprozip.filters': [
              'python = reprozip.filters:python',
              'builtin = reprozip.filters:builtin']},
      install_requires=req,
      description="Linux tool enabling reproducible experiments (packer)",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='reprozip-users@vgc.poly.edu',
      maintainer="Remi Rampin",
      maintainer_email='remirampin@gmail.com',
      url='http://vida-nyu.github.io/reprozip/',
      long_description=description,
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: C',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
