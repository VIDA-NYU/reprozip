from setuptools import setup, Extension


# List the source files
sources = ['pytracer.c', 'tracer.c', 'database.c', 'ptrace_utils.c']


# Setup the libraries
libraries = ['sqlite3', 'rt']


# Build the C module
pytracer = Extension('reprozip._pytracer',
                     sources=sources,
                     libraries=libraries)

description = """
ReproZip is a tool aimed at scientists using Linux distributions, that
simplifies the process of creating reproducible experiments from programs.

It uses the ptrace facilities of Linux to trace the processes and files that
are part of the experiment and build a comprehensive provenance graph for the
user to review.

Then, it can pack these files in a package to allow for easy reproducibility
elsewhere, either by unpacking and running on a compatible machine or by
creating a virtual machine through Vagrant.
"""
setup(name='reprozip',
      version='0.0',
      ext_modules=[pytracer],
      packages=['reprozip', 'reprozip.tracer'],
      entry_points={
        'console_scripts': [
          'reprozip = reprozip.main:main']},
      install_requires=[
        'PyYAML'],
      description='Linux tool enabling reproducible experiments',
      author="Remi Rampin",
      author_email='remirampin@gmail.com',
      url='http://github.com/remram44/reprozip',
      long_description=description,
      license='BSD',
      keywords=['reprozip', 'reproducibility', 'provenance'],
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Archiving'])
