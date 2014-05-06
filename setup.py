try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
import os
import re
import sys


# List the source files
sources = ['pytracer.c', 'tracer.c', 'database.c']


# Setup the libraries
libraries = ['sqlite3', 'rt']


# Build the C module
pytracer = Extension('reprozip._pytracer',
                     sources=sources,
                     libraries=libraries)

description = """
TODO
"""
setup(name='reprozip',
      version='0.0',
      ext_modules=[pytracer],
      packages=['reprozip'],
      description='Reprozip -- TODO',
      author="Remi Rampin",
      author_email='remirampin@gmail.com',
      #url='http://github.com/remram44/reprozip',
      long_description=description,
      license='MIT',
      keywords=['reprozip', 'reproducibility', 'provenance'],
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Archiving'])
