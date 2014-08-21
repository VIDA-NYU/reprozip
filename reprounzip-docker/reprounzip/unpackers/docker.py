"""Docker plugin for reprounzip.

This files contains the 'docker' unpacker, which builds a Dockerfile from a
reprozip pack. You can then build a container and run it with Docker.

See http://www.docker.io/
"""

# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import os
from rpaths import Path, PosixPath
import sys

from reprounzip.unpackers.common import load_config, select_installer, \
    COMPAT_OK, COMPAT_MAYBE, join_root, shell_escape
import tarfile
import logging
from reprounzip.utils import unicode_


def docker_escape(s):
    return '"%s"' % (s.replace('\\', '\\\\')
                      .replace('"', '\\"'))


def select_image(runs):
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    if architecture == 'i686':
        sys.stderr.write("Warning: wanted architecture was i686, but we'll "
                         "use x86_64 with Docker")
    elif architecture != 'x86_64':
        sys.stderr.write("Error: unsupported architecture %s\n" % architecture)
        sys.exit(1)

    # Ubuntu
    if distribution == 'ubuntu':
        if version != '12.04':
            sys.stderr.write("Warning: using Ubuntu 12.04 'Precise' instead "
                             "of '%s'\n" % version)
        return 'ubuntu', 'ubuntu:12.04'

    # Debian
    elif distribution != 'debian':
        sys.stderr.write("Warning: unsupported distribution %s, using Debian"
                         "\n" % distribution)
        distribution = 'debian', '7'

    if version == '6' or version.startswith('squeeze'):
        return 'debian', 'debian:squeeze'
    else:
        if version != '7' and not version.startswith('wheezy'):
            sys.stderr.write("Warning: using Debian 7 'Wheezy' instead of '%s'"
                             "\n" % version)
        return 'debian', 'debian:wheezy'


def create_docker(args):
    """Sets up the experiment to be run in a Docker-built container.
    """
    pack = Path(args.pack[0])
    target = Path(args.target[0])
    if target.exists():
        sys.stderr.write("Error: Target directory exists\n")
        sys.exit(1)

    # Loads config
    runs, packages, other_files = load_config(pack)

    if args.base_image:
        target_distribution = None
        base_image = args.base_image[0]
    else:
        target_distribution, base_image = select_image(runs)

    target.mkdir(parents=True)
    pack.copyfile(target / 'experiment.rpz')

    # Writes Dockerfile
    with (target / 'Dockerfile').open('w',
                                      encoding='utf-8', newline='\n') as fp:
        fp.write('FROM %s\n\n' % base_image)
        fp.write('COPY experiment.rpz /reprozip_experiment.rpz\n\n')
        fp.write('RUN \\\n')

        # Installs missing packages
        packages = [pkg for pkg in packages if not pkg.packfiles]
        if packages:
            installer = select_installer(pack, runs, target_distribution)
            # Updates package sources
            fp.write('    %s && \\\n' % installer.update_script())
            # Installs necessary packages
            fp.write('    %s && \\\n' % installer.install_script(packages))

        # Untar
        paths = set()
        pathlist = []
        dataroot = PosixPath('DATA')
        # Adds intermediate directories, and checks for existence in the tar
        tar = tarfile.open(str(pack), 'r:*')
        for f in other_files:
            path = PosixPath('/')
            for c in f.path.components[1:]:
                path = path / c
                if path in paths:
                    continue
                paths.add(path)
                datapath = join_root(dataroot, path)
                try:
                    tar.getmember(str(datapath))
                except KeyError:
                    logging.info("Missing file %s" % datapath)
                else:
                    pathlist.append(unicode_(datapath))
        tar.close()
        # FIXME : for some reason we need reversed() here, I'm not sure why.
        # Need to read more of tar's docs.
        # TAR bug: --no-overwrite-dir removes --keep-old-files
        fp.write('    cd / && tar zpxf /reprozip_experiment.rpz '
                 '--numeric-owner --strip=1 %s\n' %
                 ' '.join(shell_escape(p) for p in reversed(pathlist)))

        # TODO


def test_has_docker(pack, **kwargs):
    pathlist = os.environ['PATH'].split(os.pathsep) + ['.']
    pathexts = os.environ.get('PATHEXT', '').split(os.pathsep)
    for path in pathlist:
        for ext in pathexts:
            fullpath = os.path.join(path, 'docker') + ext
            if os.path.isfile(fullpath):
                return COMPAT_OK
    return COMPAT_MAYBE, "docker not found in PATH"


def setup(parser):
    """Unpacks the files and sets up the experiment to be run with Docker
    """
    # Creates a virtual machine with Vagrant
    parser.add_argument('pack', nargs=1, help="Pack to extract")
    parser.add_argument('target', nargs=1, help="Directory to create")
    parser.add_argument('--base-image', nargs=1, help="Base image to use")
    parser.set_defaults(func=create_docker)

    return {'test_compatibility': test_has_docker}
