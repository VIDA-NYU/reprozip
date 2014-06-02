from setuptools import setup


description = """\
ReproZip is a tool aimed at scientists using Linux distributions, that
simplifies the process of creating reproducible experiments from programs.

It uses the ptrace facilities of Linux to trace the processes and files that
are part of the experiment and build a comprehensive provenance graph for the
user to review.

Then, it can pack these files in a package to allow for easy reproducibility
elsewhere, either by unpacking and running on a compatible machine or by
creating a virtual machine through Vagrant.

This package holds the unpacker components (and the 'reprounzip' command-line
utility).
"""
setup(name='reprounzip',
      version='0.0',
      packages=['reprounzip', 'reprounzip.unpackers'],
      entry_points={
          'console_scripts': [
              'reprounzip = reprounzip.reprounzip:main'],
          'reprounzip.unpackers': [
              'graph = reprounzip.unpackers.graph:setup',
              'default = reprounzip.unpackers.default:setup']},
      namespace_packages=['reprounzip', 'reprounzip.unpackers'],
      install_requires=[
          'PyYAML'],
      description='Linux tool enabling reproducible experiments (unpacker)',
      author="Remi Rampin",
      author_email='remirampin@gmail.com',
      url='http://github.com/remram44/reprozip',
      long_description=description,
      license='BSD',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance'],
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
