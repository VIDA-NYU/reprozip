import io
import os
from setuptools import setup


os.chdir(os.path.abspath(os.path.dirname(__file__)))


with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
setup(name='reprounzip-docker',
      version='2.0.0',
      py_modules=['reprounzip_docker'],
      entry_points={
          'reprounzip.unpackers': [
              'docker = reprounzip_docker:setup']},
      install_requires=[
          'reprounzip>=2.0.0,<3.0.0'],
      description="Allows the ReproZip unpacker to create Docker containers",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='dev@reprozip.org',
      maintainer="Remi Rampin",
      maintainer_email='remi@rampin.org',
      url='https://www.reprozip.org/',
      project_urls={
          'Homepage': 'https://github.com/ViDA-NYU/reprozip',
          'Documentation': 'https://docs.reprozip.org/',
          'Examples': 'https://examples.reprozip.org/',
          'Say Thanks': 'https://saythanks.io/to/remram44',
          'Source': 'https://github.com/ViDA-NYU/reprozip',
          'Tracker': 'https://github.com/ViDA-NYU/reprozip/issues',
      },
      long_description=description,
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu', 'docker'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
