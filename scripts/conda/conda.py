#!/usr/bin/env python
from __future__ import print_function

import os
from os.path import join
import re
import shutil
import struct
import subprocess
import sys
import tempfile


# This script automatically builds Conda packages

if len(sys.argv) < 2:
    print("Usage: {0} <target_directory> [version]".format(sys.argv[0]),
          file=sys.stderr)
    sys.exit(1)

dest_dir = sys.argv[1]
top_level = join(os.path.dirname(sys.argv[0]), '..', '..')

# Clears Conda cache
anaconda_cache = join(os.environ['CONDA_PREFIX'], 'conda-bld', 'src_cache')
if os.path.exists(anaconda_cache):
    shutil.rmtree(anaconda_cache)

if len(sys.argv) < 3:
    version = subprocess.check_output(['git', 'describe', '--tags']).strip()
    # describe gives us either "0.5" or "0.5-40-g1234567"
    # if the latter, convert it to 0.5.40
    version = re.sub(r'^([0-9.]*)-([0-9]*)-g([a-f0-9]*)$', '\\1.\\2', version)
else:
    version = sys.argv[2]


if sys.platform == 'darwin':
    osname = 'osx'
elif sys.platform.startswith('linux'):
    osname = 'linux'
elif sys.platform.startswith('win'):
    osname = 'win'
else:
    raise ValueError("Unknown platform")

bits = struct.calcsize('P') * 8

arch = '{0}-{1}'.format(osname, bits)

for python_ver in ('2.7', '3.4', '3.5', '3.6'):
    for package_name in ('reprozip', 'reprounzip', 'reprounzip-docker',
                         'reprounzip-vagrant', 'reprounzip-vistrails',
                         'reprozip-jupyter', 'reprounzip-qt'):
        if package_name == 'reprozip' and osname != 'linux':
            continue
        if package_name == 'reprounzip-qt' and python_ver != '2.7':
            continue

        temp_dir = tempfile.mkdtemp(prefix='rr_conda_')
        os.mkdir(join(temp_dir, 'croot'))

        pkgdir = join(top_level, package_name)

        try:
            # Builds source distribution
            subprocess.check_call(['python', 'setup.py', 'sdist',
                                   '--dist-dir', temp_dir], cwd=pkgdir)

            # Rename it
            temp_file, = os.listdir(temp_dir)
            shutil.move(join(temp_dir, temp_file),
                        join(temp_dir, '{0}.tar.gz'.format(package_name)))

            # Copies conda recipe
            shutil.copytree(join(top_level, 'scripts', 'conda', package_name),
                            join(temp_dir, package_name))

            # Update recipe
            with open(join(temp_dir, package_name, 'meta.yaml')) as fp:
                lines = fp.readlines()
            # Changes version in recipe
            lines = [l.replace('_REPLACE_version_REPLACE_', version)
                     for l in lines]
            with open(join(temp_dir, package_name, 'meta.yaml'), 'w') as fp:
                for line in lines:
                    # Changes version
                    line = line.replace('_REPLACE_version_REPLACE_', version)
                    # Changes URL
                    if osname == 'win':
                        line = line.replace(
                            '_REPLACE_url_REPLACE_',
                            'file:///{0}/{1}.tar.gz'.format(
                                temp_dir.replace(os.sep, '/'),
                                package_name))
                    else:
                        line = line.replace(
                            '_REPLACE_url_REPLACE_',
                            'file://{0}/{1}.tar.gz'.format(temp_dir,
                                                           package_name))
                    # Change build string
                    line = line.replace('_REPLACE_buildstr_REPLACE_',
                                        'py{0}'.format(python_ver))

                    fp.write(line)

            # Builds Conda package
            output_pkg = subprocess.check_output(['conda', 'build',
                                                  '--croot', croot,
                                                  '--python', python_ver,
                                                  '--output', package_name],
                                                 cwd=temp_dir).rstrip()
            output_pkg = join(temp_dir, output_pkg)
            subprocess.check_call(['conda', 'build',
                                   '--croot', croot,
                                   '--python', python_ver,
                                   package_name],
                                  cwd=temp_dir)

            # Copies result out
            shutil.copyfile(join(pkgdir, output_pkg),
                            join(dest_dir, os.path.basename(output_pkg)))
        finally:
            # Removes temporary directory
            shutil.rmtree(temp_dir)
            # Clears Conda cache
            if os.path.exists(anaconda_cache):
                shutil.rmtree(anaconda_cache)
