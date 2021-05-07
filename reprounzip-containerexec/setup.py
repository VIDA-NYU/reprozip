import io
import os
import setuptools

# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))

with io.open('README.rst', encoding='utf-8') as fp:
    long_description = fp.read()
setuptools.setup(
    name = 'reprounzip-containerexec',
    version = '1.0',
    author = 'Dirk Beyer',
    description = "An unpacker for reprozip using the container technology of BenchExec",
    long_description = long_description,
    url = 'https://www.reprozip.org',
    license = 'BSD-3-Clause',
    keywords = [
        'reprozip', 'reprounzip', 'reproducibility', 'provenance',
        'benchexec', 'containerexec', 'container'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Scientific/Engineering',
        'Topic :: System :: Archiving'],
    platforms = ['Linux'],

    packages = ['reprounzip', 'reprounzip.unpackers'],
    entry_points = {
        'reprounzip.unpackers': [
            'containerexec = reprounzip.unpackers.containerexec:setup']
        },
    namespace_packages = ['reprounzip', 'reprounzip.unpackers'],
    install_requires = [
        'reprounzip>=1.0.8',
        'rpaths>=0.8',
        'benchexec>=1.11',
        ],
    zip_safe = True,
    )
