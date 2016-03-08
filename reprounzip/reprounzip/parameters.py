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

from reprounzip.common import get_reprozip_ca_certificate
from reprounzip.utils import download_file


parameters = None


def update_parameters():
    """Try to download a new version of the parameter file.
    """
    global parameters
    if parameters is not None:
        return

    try:
        from reprounzip.main import __version__ as version
        filename = download_file(
            'https://reprozip-stats.poly.edu/parameters/%s' % version, None,
            cachename='parameters.json',
            ssl_verify=get_reprozip_ca_certificate().path)
    except Exception:
        logging.info("Can't download parameters.json, using bundled "
                     "parameters")
    else:
        try:
            with filename.open() as fp:
                parameters = json.load(fp)
            return
        except ValueError:
            logging.info("Downloaded parameters.json doesn't load, using "
                         "bundled parameters")
            try:
                filename.remove()
            except OSError:
                pass

    parameters = json.loads(bundled_parameters)


def get_parameter(section):
    """Get a parameter from the downloaded or default parameter file.
    """
    global parameters

    if parameters is None:
        update_parameters()

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
