from setuptools import setup
import sys


with open('README.rst') as fp:
    description = fp.read()
req = [
    'PyYAML',
    'rpaths>=0.4']
if sys.version_info < (2, 7):
    req.append('argparse')
setup(name='reprounzip',
      version='0.2.1',
      packages=['reprounzip', 'reprounzip.unpackers'],
      entry_points={
          'console_scripts': [
              'reprounzip = reprounzip.reprounzip:main'],
          'reprounzip.unpackers': [
              'graph = reprounzip.unpackers.graph:setup',
              'default = reprounzip.unpackers.default:setup']},
      namespace_packages=['reprounzip', 'reprounzip.unpackers'],
      install_requires=req,
      description="Linux tool enabling reproducible experiments (unpacker)",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='reprozip-users@vgc.poly.edu',
      maintainer="Remi Rampin",
      maintainer_email='remirampin@gmail.com',
      url='http://github.com/ViDA-NYU/reprozip',
      long_description=description,
      license='BSD',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
