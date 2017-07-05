import io
import os
from setuptools import setup


# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))


# Need to specify encoding for PY3, which has the worst unicode handling ever
with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
req = [
    'reprounzip>=1.0.8',
    'rpaths>=0.8',
    'benchexec>=1.10']
setup(name='reprounzip-containerexec',
      version='0.1',
      packages=['reprounzip', 'reprounzip.unpackers',
                'reprounzip.unpackers.containerexec'],
      entry_points={
          'reprounzip.unpackers': [
              'containerexec = reprounzip.unpackers.containerexec.default:setup']},
      namespace_packages=['reprounzip', 'reprounzip.unpackers'],
      install_requires=req,
      description="Linux tool enabling reproducible experiments (unpacker) in an isolated environment",
      author="Thomas Bunk, Philipp Wendler",
      author_email='',
      maintainer="Philipp Wendler",
      maintainer_email='',
      url='https://github.com/sosy-lab/reprozip',
      long_description=description,
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu', 'benchexec', 'containerexec', 'container',
                'sandbox'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
