# Copyright (C) 2014-2017 New York University
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

from distutils.version import LooseVersion
import json
import logging
import os

from reprounzip.common import get_reprozip_ca_certificate
from reprounzip.utils import download_file


logger = logging.getLogger('reprounzip')


parameters = None


def update_parameters():
    """Try to download a new version of the parameter file.
    """
    global parameters
    if parameters is not None:
        return

    url = 'https://stats.reprozip.org/parameters/'
    env_var = os.environ.get('REPROZIP_PARAMETERS')
    if env_var and (
            env_var.startswith('http://') or env_var.startswith('https://')):
        # This is only used for testing
        # Note that this still expects the ReproZip CA
        url = env_var
    elif env_var not in (None, '', '1', 'on', 'enabled', 'yes', 'true'):
        parameters = _bundled_parameters
        return

    try:
        from reprounzip.main import __version__ as version
        filename = download_file(
            '%s%s' % (url, version),
            None,
            cachename='parameters.json',
            ssl_verify=str(get_reprozip_ca_certificate()))
    except Exception:
        logger.warning("Can't download parameters.json, using bundled "
                       "parameters")
    else:
        try:
            with filename.open() as fp:
                parameters = json.load(fp)
        except ValueError:
            logger.info("Downloaded parameters.json doesn't load, using "
                        "bundled parameters")
            try:
                filename.remove()
            except OSError:
                pass
        else:
            ver = LooseVersion(parameters.get('version', '1.0'))
            if LooseVersion('1.0') <= ver < LooseVersion('1.1'):
                return
            else:
                logger.info("parameters.json has incompatible version %s, "
                            "using bundled parameters", ver)

    parameters = _bundled_parameters


def get_parameter(section):
    """Get a parameter from the downloaded or default parameter file.
    """
    if parameters is None:
        update_parameters()

    return parameters.get(section, None)


_bundled_parameters = {
    "busybox_url": {
        "x86_64": "https://s3.amazonaws.com/reprozip-files/busybox-x86_64",
        "i686": "https://s3.amazonaws.com/reprozip-files/busybox-i686"
    },
    "rpzsudo_url": {
        "x86_64": "https://github.com/remram44/static-sudo/releases/download/"
                  "current/rpzsudo-x86_64",
        "i686": "https://github.com/remram44/static-sudo/releases/download/"
                "current/rpzsudo-i686"
    },
    "docker_images": {
        "default": "debian",
        "images": {
            "ubuntu": {
                "versions": [
                    {
                        "version": "^12\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:12.04",
                        "name": "Ubuntu 12.04 'Precise'"
                    },
                    {
                        "version": "^14\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:14.04",
                        "name": "Ubuntu 14.04 'Trusty'"
                    },
                    {
                        "version": "^14\\.10$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:14.10",
                        "name": "Ubuntu 14.10 'Utopic'"
                    },
                    {
                        "version": "^15\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:15.04",
                        "name": "Ubuntu 15.04 'Vivid'"
                    },
                    {
                        "version": "^15\\.10$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:15.10",
                        "name": "Ubuntu 15.10 'Wily'"
                    },
                    {
                        "version": "^16\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:16.04",
                        "name": "Ubuntu 16.04 'Xenial'"
                    },
                    {
                        "version": "^16\\.10$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:16.10",
                        "name": "Ubuntu 16.10 'Yakkety'"
                    },
                    {
                        "version": "^17\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:17.04",
                        "name": "Ubuntu 17.04 'Zesty'"
                    },
                    {
                        "version": "^17\\.10$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:17.10",
                        "name": "Ubuntu 17.10 'Artful'"
                    },
                    {
                        "version": "^18\\.04$",
                        "distribution": "ubuntu",
                        "image": "ubuntu:18.04",
                        "name": "Ubuntu 18.04 'Bionic'"
                    }
                ],
                "default": {
                    "distribution": "ubuntu",
                    "image": "ubuntu:16.04",
                    "name": "Ubuntu 16.04 'Xenial'"
                }
            },
            "debian": {
                "versions": [
                    {
                        "version": "^(6(\\.|$))|(squeeze)",
                        "distribution": "debian",
                        "image": "debian:squeeze",
                        "name": "Debian 6 'Squeeze'"
                    },
                    {
                        "version": "^(7(\\.|$))|(wheezy)",
                        "distribution": "debian",
                        "image": "debian:wheezy",
                        "name": "Debian 7 'Wheezy'"
                    },
                    {
                        "version": "^(8(\\.|$))|(jessie)",
                        "distribution": "debian",
                        "image": "debian:jessie",
                        "name": "Debian 8 'Jessie'"
                    },
                    {
                        "version": "^(9(\\.|$))|(stretch)",
                        "distribution": "debian",
                        "image": "debian:stretch",
                        "name": "Debian 9 'Stretch'"
                    },
                    {
                        "version": "^(10(\\.|$))|(buster)",
                        "distribution": "debian",
                        "image": "debian:buster",
                        "name": "Debian 10 'Buster'"
                    }
                ],
                "default": {
                    "distribution": "debian",
                    "image": "debian:stretch",
                    "name": "Debian 9 'Stretch'"
                }
            },
            "centos": {
                "versions": [
                    {
                        "version": "^5(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos5",
                        "name": "CentOS 5"
                    },
                    {
                        "version": "^6(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos6",
                        "name": "CentOS 6"
                    },
                    {
                        "version": "^7(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos7",
                        "name": "CentOS 7"
                    }
                ],
                "default": {
                    "distribution": "centos",
                    "image": "centos:centos7",
                    "name": "CentOS 7"
                }
            },
            "centos linux": {
                "versions": [
                    {
                        "version": "^5(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos5",
                        "name": "CentOS 5"
                    },
                    {
                        "version": "^6(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos6",
                        "name": "CentOS 6"
                    },
                    {
                        "version": "^7(\\.|$)",
                        "distribution": "centos",
                        "image": "centos:centos7",
                        "name": "CentOS 7"
                    }
                ],
                "default": {
                    "distribution": "centos",
                    "image": "centos:centos7",
                    "name": "CentOS 7"
                }
            },
            "fedora": {
                "versions": [
                    {
                        "version": "^20$",
                        "distribution": "fedora",
                        "image": "fedora:20",
                        "name": "Fedora 20"
                    },
                    # Fedora 21-24 omitted because they don't include tar
                    {
                        "version": "^25$",
                        "distribution": "fedora",
                        "image": "fedora:25",
                        "name": "Fedora 25"
                    },
                    {
                        "version": "^26$",
                        "distribution": "fedora",
                        "image": "fedora:26",
                        "name": "Fedora 26"
                    },
                    {
                        "version": "^27$",
                        "distribution": "fedora",
                        "image": "fedora:27",
                        "name": "Fedora 27"
                    },
                    {
                        "version": "^28$",
                        "distribution": "fedora",
                        "image": "fedora:28",
                        "name": "Fedora 28"
                    },
                    {
                        "version": "^29$",
                        "distribution": "fedora",
                        "image": "fedora:29",
                        "name": "Fedora 29"
                    }
                ],
                "default": {
                    "distribution": "fedora",
                    "image": "fedora:29",
                    "name": "Fedora 29"
                }
            }
        }
    },
    "vagrant_boxes": {
        "default": "debian",
        "boxes": {
            "ubuntu": {
                "versions": [
                    {
                        "version": "^12\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "hashicorp/precise32",
                            "x86_64": "hashicorp/precise64"
                        },
                        "name": "Ubuntu 12.04 'Precise'"
                    },
                    {
                        "version": "^14\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "ubuntu/trusty32",
                            "x86_64": "ubuntu/trusty64"
                        },
                        "name": "Ubuntu 14.04 'Trusty'"
                    },
                    {
                        "version": "^15\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "ubuntu/vivid32",
                            "x86_64": "ubuntu/vivid64"
                        },
                        "name": "Ubuntu 15.04 'Vivid'"
                    },
                    {
                        "version": "^15\\.10$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "ubuntu/wily32",
                            "x86_64": "ubuntu/wily64"
                        },
                        "name": "Ubuntu 15.10 'Wily'"
                    },
                    {
                        "version": "^16\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "bento/ubuntu-16.04-i386",
                            "x86_64": "bento/ubuntu-16.04"
                        },
                        "name": "Ubuntu 16.04 'Xenial'"
                    },
                    {
                        "version": "^16\\.10$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "bento/ubuntu-16.10-i386",
                            "x86_64": "bento/ubuntu-16.10"
                        },
                        "name": "Ubuntu 16.10 'Yakkety'"
                    },
                    {
                        "version": "^17\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "bento/ubuntu-17.04-i386",
                            "x86_64": "bento/ubuntu-17.04"
                        },
                        "name": "Ubuntu 17.04 'Zesty'"
                    },
                    {
                        "version": "^17\\.10$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "bento/ubuntu-17.10-i386",
                            "x86_64": "bento/ubuntu-17.10"
                        },
                        "name": "Ubuntu 17.10 'Artful'"
                    },
                    {
                        "version": "^18\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "bento/ubuntu-18.04-i386",
                            "x86_64": "bento/ubuntu-18.04"
                        },
                        "name": "Ubuntu 18.04 'Bionic'"
                    }
                ],
                "default": {
                    "distribution": "ubuntu",
                    "architectures": {
                        "i686": "bento/ubuntu-18.04-i386",
                        "x86_64": "bento/ubuntu-18.04"
                    },
                    "name": "Ubuntu 18.04 'Bionic'"
                }
            },
            "debian": {
                "versions": [
                    {
                        "version": "^(7(\\.|$))|(wheezy)",
                        "distribution": "debian",
                        "architectures": {
                            "i686": "remram/debian-7-i386",
                            "x86_64": "remram/debian-7-amd64"
                        },
                        "name": "Debian 7 'Wheezy'"
                    },
                    {
                        "version": "^(8(\\.|$))|(jessie)",
                        "distribution": "debian",
                        "architectures": {
                            "i686": "remram/debian-8-i386",
                            "x86_64": "remram/debian-8-amd64"
                        },
                        "name": "Debian 8 'Jessie'"
                    },
                    {
                        "version": "^(9(\\.|$))|(stretch)",
                        "distribution": "debian",
                        "architectures": {
                            "i686": "remram/debian-9-i386",
                            "x86_64": "remram/debian-9-amd64"
                        },
                        "name": "Debian 9 'Stretch'"
                    }
                ],
                "default": {
                    "distribution": "debian",
                    "architectures": {
                        "i686": "remram/debian-8-i386",
                        "x86_64": "remram/debian-8-amd64"
                    },
                    "name": "Debian 8 'Jessie'"
                }
            },
            "centos": {
                "versions": [
                    {
                        "version": "^5\\.",
                        "distribution": "centos",
                        "architectures": {
                            "i686": "bento/centos-5.11-i386",
                            "x86_64": "bento/centos-5.11"
                        },
                        "name": "CentOS 5.11"
                    },
                    {
                        "version": "^6\\.",
                        "distribution": "centos",
                        "architectures": {
                            "i686": "bento/centos-6.7-i386",
                            "x86_64": "bento/centos-6.7"
                        },
                        "name": "CentOS 6.7"
                    },
                    {
                        "version": "^7\\.",
                        "distribution": "centos",
                        "architectures": {
                            "x86_64": "bento/centos-7.2"
                        },
                        "name": "CentOS 7.2"
                    }
                ],
                "default": {
                    "distribution": "centos",
                    "architectures": {
                        "i686": "bento/centos-6.7-i386",
                        "x86_64": "bento/centos-6.7"
                    },
                    "name": "CentOS 6.7"
                }
            },
            "centos linux": {
                "versions": [
                    {
                        "version": "^5\\.",
                        "distribution": "centos",
                        "architectures": {
                            "i686": "bento/centos-5.11-i386",
                            "x86_64": "bento/centos-5.11"
                        },
                        "name": "CentOS 5.11"
                    },
                    {
                        "version": "^6\\.",
                        "distribution": "centos",
                        "architectures": {
                            "i686": "bento/centos-6.7-i386",
                            "x86_64": "bento/centos-6.7"
                        },
                        "name": "CentOS 6.7"
                    },
                    {
                        "version": "^7\\.",
                        "distribution": "centos",
                        "architectures": {
                            "x86_64": "bento/centos-7.2"
                        },
                        "name": "CentOS 7.2"
                    }
                ],
                "default": {
                    "distribution": "centos",
                    "architectures": {
                        "i686": "bento/centos-6.7-i386",
                        "x86_64": "bento/centos-6.7"
                    },
                    "name": "CentOS 6.7"
                }
            },
            "fedora": {
                "versions": [
                    {
                        "version": "^22$",
                        "distribution": "fedora",
                        "architectures": {
                            "i686": "remram/fedora-22-i386",
                            "x86_64": "remram/fedora-22-amd64"
                        },
                        "name": "Fedora 22"
                    },
                    {
                        "version": "^23$",
                        "distribution": "fedora",
                        "architectures": {
                            "i686": "remram/fedora-23-i386",
                            "x86_64": "remram/fedora-23-amd64"
                        },
                        "name": "Fedora 23"
                    },
                    {
                        "version": "^24$",
                        "distribution": "fedora",
                        "architectures": {
                            "i686": "remram/fedora-24-i386",
                            "x86_64": "remram/fedora-24-amd64"
                        },
                        "name": "Fedora 24"
                    },
                    {
                        "version": "^25$",
                        "distribution": "fedora",
                        "architectures": {
                            "x86_64": "bento/fedora-25"
                        },
                        "name": "Fedora 25"
                    },
                    {
                        "version": "^26$",
                        "distribution": "fedora",
                        "architectures": {
                            "x86_64": "bento/fedora-26"
                        },
                        "name": "Fedora 26"
                    },
                    {
                        "version": "^27$",
                        "distribution": "fedora",
                        "architectures": {
                            "x86_64": "bento/fedora-27"
                        },
                        "name": "Fedora 27"
                    },
                    {
                        "version": "^28$",
                        "distribution": "fedora",
                        "architectures": {
                            "x86_64": "bento/fedora-28"
                        },
                        "name": "Fedora 28"
                    }
                ],
                "default": {
                    "distribution": "fedora",
                    "architectures": {
                        "i686": "remram/fedora-24-i386",
                        "x86_64": "remram/fedora-24-amd64"
                    },
                    "name": "Fedora 24"
                }
            }
        }
    },
    "vagrant_boxes_x": {
        "default": "debian",
        "boxes": {
            "ubuntu": {
                "versions": [
                    {
                        "version": "^16\\.04$",
                        "distribution": "ubuntu",
                        "architectures": {
                            "i686": "remram/ubuntu-1604-amd64-x",
                            "x86_64": "remram/ubuntu-1604-amd64-x"
                        },
                        "name": "Ubuntu 16.04 'Xenial'"
                    }
                ],
                "default": {
                    "distribution": "ubuntu",
                    "architectures": {
                        "i686": "remram/ubuntu-1604-amd64-x",
                        "x86_64": "remram/ubuntu-1604-amd64-x"
                    },
                    "name": "Ubuntu 16.04 'Xenial'"
                }
            },
            "debian": {
                "versions": [
                    {
                        "version": "^(8(\\.|$))|(jessie)",
                        "distribution": "debian",
                        "architectures": {
                            "i686": "remram/debian-8-amd64-x",
                            "x86_64": "remram/debian-8-amd64-x"
                        },
                        "name": "Debian 8 'Jessie'"
                    }
                ],
                "default": {
                    "distribution": "debian",
                    "architectures": {
                        "i686": "remram/debian-8-amd64-x",
                        "x86_64": "remram/debian-8-amd64-x"
                    },
                    "name": "Debian 8 'Jessie'"
                }
            }
        }
    }
}
