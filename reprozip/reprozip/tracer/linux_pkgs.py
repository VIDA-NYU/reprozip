# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Package identification routines.

This module contains the :func:`~reprozip.tracer.linux_pkgs.identify_packages`
function that sorts a list of files between their distribution packages,
depending on what Linux distribution we are running on.

Currently supported package managers:
- dpkg (Debian, Ubuntu)
"""

from __future__ import division, print_function, unicode_literals

import logging
import platform
from rpaths import Path
import subprocess
import time

from reprozip.common import Package
from reprozip.utils import iteritems, listvalues


logger = logging.getLogger('reprozip')


magic_dirs = ('/dev', '/proc', '/sys')
system_dirs = ('/bin', '/etc', '/lib', '/sbin', '/usr', '/var')


class PkgManager(object):
    """Base class for package identifiers.

    Subclasses should provide either `search_for_files` or `search_for_file`
    which actually identifies the package for a file.
    """
    def __init__(self):
        # Files that were not part of a package
        self.unknown_files = set()
        # All the packages identified, with their `files` attribute set
        self.packages = {}

    def filter_files(self, files):
        seen_files = set()
        for f in files:
            if f.path not in seen_files:
                if not self._filter(f):
                    yield f
                seen_files.add(f.path)

    def search_for_files(self, files):
        nb_pkg_files = 0

        for f in self.filter_files(files):
            pkgnames = self._get_packages_for_file(f.path)

            # Stores the file
            if not pkgnames:
                self.unknown_files.add(f)
            else:
                pkgs = []
                for pkgname in pkgnames:
                    if pkgname in self.packages:
                        pkgs.append(self.packages[pkgname])
                    else:
                        pkg = self._create_package(pkgname)
                        if pkg is not None:
                            self.packages[pkgname] = pkg
                            pkgs.append(self.packages[pkgname])
                if len(pkgs) == 1:
                    pkgs[0].add_file(f)
                    nb_pkg_files += 1
                else:
                    self.unknown_files.add(f)

        # Filter out packages with no files
        self.packages = {pkgname: pkg
                         for pkgname, pkg in iteritems(self.packages)
                         if pkg.files}

        logger.info("%d packages with %d files, and %d other files",
                    len(self.packages),
                    nb_pkg_files,
                    len(self.unknown_files))

    def _filter(self, f):
        # Special files
        if any(f.path.lies_under(c) for c in magic_dirs):
            return True

        # If it's not in a system directory, no need to look for it
        if (f.path.lies_under('/usr/local') or
                not any(f.path.lies_under(c) for c in system_dirs)):
            self.unknown_files.add(f)
            return True

        return False

    def _get_packages_for_file(self, filename):
        raise NotImplementedError

    def _create_package(self, pkgname):
        raise NotImplementedError


class DpkgManager(PkgManager):
    """Package identifier for deb-based systems (Debian, Ubuntu).
    """
    def search_for_files(self, files):
        # Make a set of all the requested files
        requested = dict((f.path, f) for f in self.filter_files(files))
        found = {}  # {path: pkgname}

        # Process /var/lib/dpkg/info/*.list
        for listfile in Path('/var/lib/dpkg/info').listdir():
            pkgname = listfile.unicodename[:-5]
            # Removes :arch
            pkgname = pkgname.split(':', 1)[0]

            if not listfile.unicodename.endswith('.list'):
                continue
            with listfile.open('rb') as fp:
                # Read paths from the file
                line = fp.readline()
                while line:
                    if line[-1:] == b'\n':
                        line = line[:-1]
                    path = Path(line)
                    # If it's one of the requested paths
                    if path in requested:
                        # If we had assigned it to a package already, undo
                        if path in found:
                            found[path] = None
                        # Else assign to the package
                        else:
                            found[path] = pkgname
                    line = fp.readline()

        # Remaining files are not from packages
        self.unknown_files.update(
            f for f in files
            if f.path in requested and found.get(f.path) is None)

        nb_pkg_files = 0

        for path, pkgname in iteritems(found):
            if pkgname is None:
                continue
            if pkgname in self.packages:
                package = self.packages[pkgname]
            else:
                package = self._create_package(pkgname)
                self.packages[pkgname] = package
            package.add_file(requested.pop(path))
            nb_pkg_files += 1

        logger.info("%d packages with %d files, and %d other files",
                    len(self.packages),
                    nb_pkg_files,
                    len(self.unknown_files))

    def _get_packages_for_file(self, filename):
        # This method is no longer used for dpkg: instead of querying each file
        # using `dpkg -S`, we read all the list files once ourselves since it
        # is faster
        assert False

    def _create_package(self, pkgname):
        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package}\t'
                              '${Version}\t'
                              '${Installed-Size}\n',
                              '-W',
                              pkgname],
                             stdout=subprocess.PIPE)
        try:
            size = version = None
            for line in p.stdout:
                fields = line.split()
                # Removes :arch
                name = fields[0].decode('ascii').split(':', 1)[0]
                if name == pkgname:
                    version = fields[1].decode('ascii')
                    size = int(fields[2].decode('ascii')) * 1024    # kbytes
                    break
            for line in p.stdout:  # finish draining stdout
                pass
        finally:
            p.wait()
        if p.returncode == 0:
            pkg = Package(pkgname, version, size=size)
            logger.debug("Found package %s", pkg)
            return pkg
        else:
            return None


class RpmManager(PkgManager):
    """Package identifier for rpm-based systems (Fedora, CentOS).
    """
    def _get_packages_for_file(self, filename):
        p = subprocess.Popen(['rpm', '-qf', filename.path,
                              '--qf', '%{NAME}'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            return None
        return [line.strip().decode('iso-8859-1')
                for line in out.splitlines()
                if line]

    def _create_package(self, pkgname):
        p = subprocess.Popen(['rpm', '-q', pkgname,
                              '--qf', '%{VERSION}-%{RELEASE} %{SIZE}'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode == 0:
            version, size = out.strip().decode('iso-8859-1').rsplit(' ', 1)
            size = int(size)
            pkg = Package(pkgname, version, size=size)
            logger.debug("Found package %s", pkg)
            return pkg
        else:
            return None


def identify_packages(files):
    """Organizes the files, using the distribution's package manager.
    """
    distribution = platform.linux_distribution()[0].lower()
    if distribution in ('debian', 'ubuntu'):
        logger.info("Identifying Debian packages for %d files...", len(files))
        manager = DpkgManager()
    elif (distribution in ('centos', 'centos linux',
                           'fedora', 'scientific linux') or
            distribution.startswith('red hat')):
        logger.info("Identifying RPM packages for %d files...", len(files))
        manager = RpmManager()
    else:
        logger.info("Unknown distribution, can't identify packages")
        return files, []

    begin = time.time()
    manager.search_for_files(files)
    logger.debug("Assigning files to packages took %f seconds",
                 (time.time() - begin))

    return manager.unknown_files, listvalues(manager.packages)
