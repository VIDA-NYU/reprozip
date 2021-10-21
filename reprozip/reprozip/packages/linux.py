# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Package identification for Linux distributions.

This module contains the package identification for Linux distributions.

Currently supported package managers:
- dpkg (Debian, Ubuntu)
- rpm (CentOS, Fedora)
"""

import itertools
import logging
from pathlib import Path, PurePosixPath
import subprocess

from reprozip_core.common import Package, PackageEnvironment


logger = logging.getLogger('reprozip')


magic_dirs = ('/dev', '/proc', '/sys')
system_dirs = ('/bin', '/etc', '/lib', '/sbin', '/usr', '/var', '/run')


class BaseLinuxPackages(object):
    """Base class for package identifiers.

    Subclasses should provide either `search_for_files` or `search_for_file`
    which actually identifies the package for a file.
    """
    NAME = None

    def __init__(self):
        # Files that were not part of a package
        self.unknown_files = set()
        # All the packages identified, with their `files` attribute set
        self._packages = {}

    @property
    def package_envs(self):
        assert self.NAME is not None
        return [PackageEnvironment(self.NAME, '/', self._packages.values())]

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
                    if pkgname in self._packages:
                        pkgs.append(self._packages[pkgname])
                    else:
                        pkg = self._create_package(pkgname)
                        if pkg is not None:
                            self._packages[pkgname] = pkg
                            pkgs.append(self._packages[pkgname])
                if len(pkgs) == 1:
                    pkgs[0].add_file(f)
                    nb_pkg_files += 1
                else:
                    self.unknown_files.add(f)

        # Filter out packages with no files
        self._packages = {pkgname: pkg
                          for pkgname, pkg in self._packages.items()
                          if pkg.files}

        logger.info("%d packages with %d files, and %d other files",
                    len(self._packages),
                    nb_pkg_files,
                    len(self.unknown_files))

    def _filter(self, f):
        # Special files
        if any(PurePosixPath(c) in f.path.parents for c in magic_dirs):
            return True

        # If it's not in a system directory, no need to look for it
        if (
            PurePosixPath('/usr/local') in f.path.parents or
            not any(PurePosixPath(c) in f.path.parents for c in system_dirs)
        ):
            self.unknown_files.add(f)
            return True

        return False

    def _get_packages_for_file(self, filename):
        raise NotImplementedError

    def _create_package(self, pkgname):
        raise NotImplementedError


# Before Linux 2.6.23, maximum argv is 128kB
MAX_ARGV = 800


class DebPackages(BaseLinuxPackages):
    """Package identifier for deb-based systems (Debian, Ubuntu).
    """
    NAME = 'dpkg'

    def search_for_files(self, files):
        # Make a set of all the requested files
        requested = dict((f.path, f) for f in self.filter_files(files))
        found = {}  # {path: pkgname}

        # Request a few files at a time so we don't hit the command-line size
        # limit
        iter_batch = iter(requested)
        while True:
            batch = list(itertools.islice(iter_batch, MAX_ARGV))
            if not batch:
                break

            proc = subprocess.Popen(['dpkg-query', '-S'] +
                                    [path for path in batch],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            out, err = proc.communicate()
            for line in out.splitlines():
                pkgname, path = line.split(b': ', 1)
                path = Path(path.strip().decode('utf-8', 'surrogateescape'))
                # 8-bit safe encoding, because this might be a localized error
                # message (that we don't care about)
                pkgname = pkgname.decode('iso-8859-1')
                if ', ' in pkgname:  # Multiple packages
                    found[path] = None
                    continue
                pkgname = pkgname.split(':', 1)[0]  # Remove :arch
                if path in requested:
                    if ' ' not in pkgname:
                        # If we had assigned it to a package already, undo
                        if path in found:
                            found[path] = None
                        # Else assign to the package
                        else:
                            found[path] = pkgname

        # Remaining files are not from packages
        self.unknown_files.update(
            f for f in files
            if f.path in requested and found.get(f.path) is None)

        nb_pkg_files = 0

        for path, pkgname in found.items():
            if pkgname is None:
                continue
            if pkgname in self._packages:
                package = self._packages[pkgname]
            else:
                package = self._create_package(pkgname)
                self._packages[pkgname] = package
            package.add_file(requested.pop(path))
            nb_pkg_files += 1

        logger.info("%d packages with %d files, and %d other files",
                    len(self._packages),
                    nb_pkg_files,
                    len(self.unknown_files))

    def _get_packages_for_file(self, filename):
        # This method is not used for dpkg: instead, we query multiple files at
        # once since it is faster
        assert False

    def _create_package(self, pkgname):
        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package}\t'
                              '${Version}\t'
                              '${Installed-Size}\t'
                              '${Section}\n',
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
                    section = fields[3].decode('ascii')
                    break
            for line in p.stdout:  # finish draining stdout
                pass
        finally:
            p.wait()
        if p.returncode == 0:
            pkg = Package(pkgname, version, size=size,
                          meta={'section': section})
            logger.debug("Found package %s", pkg)
            return pkg
        else:
            return None


class RpmPackages(BaseLinuxPackages):
    """Package identifier for rpm-based systems (Fedora, CentOS).
    """
    NAME = 'rpm'

    def _get_packages_for_file(self, filename):
        p = subprocess.Popen(['rpm', '-qf', filename,
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
