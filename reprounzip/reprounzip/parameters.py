# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Retrieve parameters from online source.

Most unpackers require some parameters that are likely to change on a different
schedule from ReproZip's releases. To account for that, ReproZip downloads a
"parameter file", which is just a JSON with a bunch of parameters.

In there you will find things like the address of some binaries that are
downloaded from the web (rpzsudo and busybox), and the name of Vagrant boxes
and Docker images for various operating systems.
"""

from __future__ import division, print_function, unicode_literals

import json
import logging
from rpaths import Path


parameters = None


def update_parameters():
    """Try to download a new version of the parameter file.
    """
    global parameters
    if parameters is not None:
        return

    # TODO


def get_parameter(section):
    """Get a parameter from the downloaded or default parameter file.
    """
    global parameters

    if parameters is None:
        update_parameters()
        try:
            fp = (Path('~/.reprozip').expand_user() / 'parameters.json').open()
        except IOError:
            logging.info("No parameters.json file, using bundled parameters")
            parameters = json.loads(bundled_parameters)
        else:
            parameters = json.load(fp)
            fp.close()

    return parameters.get(section, None)


bundled_parameters = (
    '{\n'
    '  "busybox_url": {\n'
    '    "x86_64": "https://www.busybox.net/downloads/binaries/latest/busybox-'
    'x86_64",\n'
    '    "i686": "https://www.busybox.net/downloads/binaries/latest/busybox-i6'
    '86"\n'
    '  },\n'
    '  "rpzsudo_url": {\n'
    '    "x86_64": "https://github.com/remram44/static-sudo/releases/download/'
    'current/rpzsudo-x86_64",\n'
    '    "i686": "https://github.com/remram44/static-sudo/releases/download/cu'
    'rrent/rpzsudo-i686"\n'
    '  }\n'
    '}\n'
)
