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
import sys

from reprounzip.unpackers.common import COMPAT_OK, COMPAT_MAYBE


def create_docker(args):
    sys.stderr.write("Docker command not yet implemented!")


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
    parser.set_defaults(func=create_docker)

    return {'test_compatibility': test_has_docker}
