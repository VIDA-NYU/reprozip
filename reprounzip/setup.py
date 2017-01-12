import io
import os
from setuptools import setup


# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))


# Need to specify encoding for PY3, which has the worst unicode handling ever
with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
req = [
    'PyYAML',
    'rpaths>=0.8',
    'usagestats>=0.3',
    'requests']
setup(name='reprounzip',
      version='1.1.0',
      packages=['reprounzip', 'reprounzip.unpackers',
                'reprounzip.unpackers.common', 'reprounzip.plugins'],
      entry_points={
          'console_scripts': [
              'reprounzip = reprounzip.main:main'],
          'reprounzip.unpackers': [
              'info = reprounzip.pack_info:setup_info',
              'showfiles = reprounzip.pack_info:setup_showfiles',
              'graph = reprounzip.unpackers.graph:setup',
              'installpkgs = reprounzip.unpackers.default:setup_installpkgs',
              'directory = reprounzip.unpackers.default:setup_directory',
              'chroot = reprounzip.unpackers.default:setup_chroot']},
      namespace_packages=['reprounzip', 'reprounzip.unpackers'],
      install_requires=req,
      extras_require={
          'all': ['reprounzip-vagrant>=1.0', 'reprounzip-docker>=1.0',
                  'reprounzip-vistrails>=1.0']},
      description="Linux tool enabling reproducible experiments (unpacker)",
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
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
