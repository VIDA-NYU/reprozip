# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Package identification routines.

This module contains the :func:`~reprozip.tracer.linux_pkgs.identify_packages`
function that sorts a list of files between their distribution packages,
depending on what Linux distribution we are running on.

Currently supported package managers:
- dpkg (Debian, Ubuntu)
"""

from __future__ import unicode_literals

import platform
from rpaths import Path
import subprocess

from reprozip.common import Package
from reprozip.utils import listvalues


magic_dirs = ('/dev', '/proc', '/sys')
system_dirs = ('/bin', '/etc', '/lib', '/sbin', '/usr', '/var')


class DpkgManager(object):
    """Package identifier for deb-based systems (Debian, Ubuntu).
    """
    def __init__(self):
        self.unknown_files = set()
        self.packages = {}
        self.package_files = {}

    def search_for_file(self, f):
        # Special files
        if any(f.path.lies_under(c) for c in magic_dirs):
            return

        # If it's not in a system directory, no need to look for it
        if (f.path.lies_under('/usr/local') or
                not any(f.path.lies_under(c) for c in system_dirs)):
            self.unknown_files.add(f)
            return

        # Looks in our cache
        if f.path in self.package_files:
            pkgname = self.package_files[f.path]
        else:
            pkgname = self._get_package_for_file(f.path)
            self.package_files[f.path] = pkgname

        # Stores the file
        if pkgname is None:
            self.unknown_files.add(f)
        else:
            if pkgname in self.packages:
                self.packages[pkgname].add_file(f)
            else:
                self._create_package(pkgname, [f])

    def _get_package_for_file(self, filename):
        p = subprocess.Popen(['dpkg', '-S', filename.path],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        for l in out.splitlines():
            pkgname, f = l.split(b': ', 1)
            f = Path(f.strip())
            # 8-bit safe encoding, because this might be a localized error
            # message (that we don't care about)
            pkgname = (pkgname.decode('iso-8859-1')
                              .split(':', 1)[0])    # Removes :arch
            self.package_files[f] = pkgname
            if f == filename:
                if ' ' not in pkgname:
                    return pkgname
        return None

    def _create_package(self, pkgname, files):
        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package;-50}\t'
                              '${Version}\t'
                              '${Installed-Size}\n',
                              '-W',
                              pkgname],
                             stdout=subprocess.PIPE)
        try:
            size = version = None
            for l in p.stdout:
                fields = l.split()
                # Removes :arch
                name = fields[0].decode('ascii').split(':', 1)[0]
                if name == pkgname:
                    version = fields[1].decode('ascii')
                    size = int(fields[2].decode('ascii')) * 1024    # kbytes
                    break
        finally:
            p.wait()
        assert p.returncode == 0
        pkg = Package(pkgname, version, files, size=size)
        self.packages[pkgname] = pkg
        return pkg


def identify_packages(files):
    """Organizes the files, using the distribution's package manager.
    """
    distribution = platform.linux_distribution()[0].lower()
    if distribution == 'ubuntu':
        manager = DpkgManager()
    elif distribution == 'debian':
        manager = DpkgManager()
    else:
        return files, []

    for f in files:
        manager.search_for_file(f)

    return manager.unknown_files, listvalues(manager.packages)
