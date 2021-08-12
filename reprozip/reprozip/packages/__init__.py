# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import distro
import logging
import time

from . import linux


logger = logging.getLogger('reprozip')


def identify_packages(files):
    """Organizes the files, using the distribution's package manager.
    """
    distribution = distro.id()
    if distribution in ('debian', 'ubuntu'):
        logger.info("Identifying Debian packages for %d files...", len(files))
        manager = linux.DebPackages()
    elif (distribution in ('centos', 'centos linux',
                           'fedora', 'scientific linux') or
            distribution.startswith('red hat')):
        logger.info("Identifying RPM packages for %d files...", len(files))
        manager = linux.RpmPackages()
    else:
        logger.info("Unknown distribution, can't identify packages")
        return files, []

    begin = time.time()
    manager.search_for_files(files)
    logger.debug("Assigning files to packages took %f seconds",
                 (time.time() - begin))

    return manager.unknown_files, manager.package_envs
