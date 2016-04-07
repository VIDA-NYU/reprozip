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
import os

from reprounzip.common import get_reprozip_ca_certificate
from reprounzip.utils import download_file


parameters = None


def update_parameters():
    """Try to download a new version of the parameter file.
    """
    global parameters
    if parameters is not None:
        return

    url = 'https://reprozip-stats.poly.edu/parameters/'
    env_var = os.environ.get('REPROZIP_PARAMETERS')
    if env_var not in (None, '', '1', 'on', 'enabled', 'yes', 'true') and (
            env_var.startswith('http://') or env_var.startswith('https://')):
        # This is only used for testing
        # Note that this still expects the ReproZip CA
        url = env_var

    try:
        from reprounzip.main import __version__ as version
        filename = download_file(
            '%s%s' % (url, version),
            None,
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
    if parameters is None:
        update_parameters()

    return parameters.get(section, None)


bundled_parameters = (
    '{\n'
    '  "busybox_url": {\n'
    '    "x86_64": "https://s3.amazonaws.com/reprozip-files/busybox-x86_64",\n'
    '    "i686": "https://s3.amazonaws.com/reprozip-files/busybox-i686"\n'
    '  },\n'
    '  "rpzsudo_url": {\n'
    '    "x86_64": "https://github.com/remram44/static-sudo/releases/download/'
    'current/rpzsudo-x86_64",\n'
    '    "i686": "https://github.com/remram44/static-sudo/releases/download/cu'
    'rrent/rpzsudo-i686"\n'
    '  },\n'
    '  "docker_images": {\n'
    '    "default": "debian",\n'
    '    "images": {\n'
    '      "ubuntu": {\n'
    '        "versions": [\n'
    '          {\n'
    '            "version": "^12\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:12.04",\n'
    '            "name": "Ubuntu 12.04 \'Precise\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^14\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:14.04",\n'
    '            "name": "Ubuntu 14.04 \'Trusty\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^14\\\\.10$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:14.10",\n'
    '            "name": "Ubuntu 14.10 \'Utopic\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^15\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:15.04",\n'
    '            "name": "Ubuntu 15.04 \'Vivid\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^15\\\\.10$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:15.10",\n'
    '            "name": "Ubuntu 15.10 \'Wily\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^16\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "image": "ubuntu:16.04",\n'
    '            "name": "Ubuntu 16.04 \'Xenial\'"\n'
    '          }\n'
    '        ],\n'
    '        "default": {\n'
    '          "distribution": "ubuntu",\n'
    '          "image": "ubuntu:15.10",\n'
    '          "name": "Ubuntu 15.10 \'Wily\'"\n'
    '        }\n'
    '      },\n'
    '      "debian": {\n'
    '        "versions": [\n'
    '          {\n'
    '            "version": "^(6(\\\\.|$))|(squeeze$)",\n'
    '            "distribution": "debian",\n'
    '            "image": "debian:squeeze",\n'
    '            "name": "Debian 6 \'Squeeze\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^(7(\\\\.|$))|(wheezy$)",\n'
    '            "distribution": "debian",\n'
    '            "image": "debian:wheezy",\n'
    '            "name": "Debian 7 \'Wheezy\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^(8(\\\\.|$))|(jessie$)",\n'
    '            "distribution": "debian",\n'
    '            "image": "debian:jessie",\n'
    '            "name": "Debian 8 \'Jessie\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^(9(\\\\.|$))|(stretch$)",\n'
    '            "distribution": "debian",\n'
    '            "image": "debian:stretch",\n'
    '            "name": "Debian 9 \'Stretch\'"\n'
    '          }\n'
    '        ],\n'
    '        "default": {\n'
    '          "distribution": "debian",\n'
    '          "image": "debian:jessie",\n'
    '          "name": "Debian 8 \'Jessie\'"\n'
    '        }\n'
    '      }\n'
    '    }\n'
    '  },\n'
    '  "vagrant_boxes": {\n'
    '    "default": "debian",\n'
    '    "boxes": {\n'
    '      "ubuntu": {\n'
    '        "versions": [\n'
    '          {\n'
    '            "version": "^12\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "architectures": {\n'
    '              "i686": "hashicorp/precise32",\n'
    '              "x86_64": "hashicorp/precise64"\n'
    '            },\n'
    '            "name": "Ubuntu 12.04 \'Precise\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^14\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "architectures": {\n'
    '              "i686": "ubuntu/trusty32",\n'
    '              "x86_64": "ubuntu/trusty64"\n'
    '            },\n'
    '            "name": "Ubuntu 14.04 \'Trusty\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^15\\\\.04$",\n'
    '            "distribution": "ubuntu",\n'
    '            "architectures": {\n'
    '              "i686": "ubuntu/vivid32",\n'
    '              "x86_64": "ubuntu/vivid64"\n'
    '            },\n'
    '            "name": "Ubuntu 15.04 \'Vivid\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^15\\\\.10$",\n'
    '            "distribution": "ubuntu",\n'
    '            "architectures": {\n'
    '              "i686": "ubuntu/wily32",\n'
    '              "x86_64": "ubuntu/wily64"\n'
    '            },\n'
    '            "name": "Ubuntu 15.10 \'Wily\'"\n'
    '          }\n'
    '        ],\n'
    '        "default": {\n'
    '          "distribution": "ubuntu",\n'
    '          "architectures": {\n'
    '            "i686": "ubuntu/wily32",\n'
    '            "x86_64": "ubuntu/wily64"\n'
    '          },\n'
    '          "name": "Ubuntu 15.10 \'Wily\'"\n'
    '        }\n'
    '      },\n'
    '      "debian": {\n'
    '        "versions": [\n'
    '          {\n'
    '            "version": "^(7(\\\\.|$))|(wheezy$)",\n'
    '            "distribution": "debian",\n'
    '            "architectures": {\n'
    '              "i686": "remram/debian-7-i386",\n'
    '              "x86_64": "remram/debian-7-amd64"\n'
    '            },\n'
    '            "name": "Debian 7 \'Wheezy\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^(8(\\\\.|$))|(jessie$)",\n'
    '            "distribution": "debian",\n'
    '            "architectures": {\n'
    '              "i686": "remram/debian-8-i386",\n'
    '              "x86_64": "remram/debian-8-amd64"\n'
    '            },\n'
    '            "name": "Debian 8 \'Jessie\'"\n'
    '          },\n'
    '          {\n'
    '            "version": "^(9(\\\\.|$))|(stretch$)",\n'
    '            "distribution": "debian",\n'
    '            "architectures": {\n'
    '              "i686": "remram/debian-9-i386",\n'
    '              "x86_64": "remram/debian-9-amd64"\n'
    '            },\n'
    '            "name": "Debian 9 \'Stretch\'"\n'
    '          }\n'
    '        ],\n'
    '        "default": {\n'
    '          "distribution": "debian",\n'
    '            "architectures": {\n'
    '              "i686": "remram/debian-8-i386",\n'
    '              "x86_64": "remram/debian-8-amd64"\n'
    '            },\n'
    '          "name": "Debian 8 \'Jessie\'"\n'
    '        }\n'
    '      }\n'
    '    }\n'
    '  }\n'
    '}\n'
)
