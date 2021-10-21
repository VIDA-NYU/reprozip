# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import logging
from pkg_resources import iter_entry_points
import time


logger = logging.getLogger('reprozip')


def identify_packages(files):
    """Organizes the files, using package managers.
    """
    unknown_files = set(files)
    package_envs = []

    for entry_point in iter_entry_points('reprozip.packagemanagers'):
        class_ = entry_point.load()
        name = entry_point.name

        logger.info("Running package manager plugin %s", name)
        manager = class_()
        begin = time.time()
        manager.search_for_files(files)
        logger.debug("Package manager plugin %s took %f seconds",
                     (time.time() - begin))
        package_envs.extend(manager.package_envs)

        # Update unknown files
        for package_env in manager.package_envs:
            for package in package_env.packages:
                unknown_files.difference_update(package.files)

    return list(unknown_files), package_envs
