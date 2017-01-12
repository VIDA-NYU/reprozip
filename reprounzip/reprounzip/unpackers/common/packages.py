# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions dealing with package managers.
"""

from __future__ import division, print_function, unicode_literals

import logging
import platform
import subprocess

from reprounzip.unpackers.common.misc import UsageError
from reprounzip.utils import itervalues


THIS_DISTRIBUTION = platform.linux_distribution()[0].lower()


PKG_NOT_INSTALLED = "(not installed)"


class CantFindInstaller(UsageError):
    def __init__(self, msg="Can't select a package installer"):
        UsageError.__init__(self, msg)


class AptInstaller(object):
    """Installer for deb-based systems (Debian, Ubuntu).
    """
    def __init__(self, binary):
        self.bin = binary

    def install(self, packages, assume_yes=False):
        # Installs
        options = []
        if assume_yes:
            options.append('-y')
        required_pkgs = set(pkg.name for pkg in packages)
        r = subprocess.call([self.bin, 'install'] +
                            options + list(required_pkgs))

        # Checks on packages
        pkgs_status = self.get_packages_info(packages)
        for pkg, status in itervalues(pkgs_status):
            if status is not None:
                required_pkgs.discard(pkg.name)
        if required_pkgs:
            logging.error("Error: some packages could not be installed:%s",
                          ''.join("\n    %s" % pkg for pkg in required_pkgs))

        return r, pkgs_status

    @staticmethod
    def get_packages_info(packages):
        if not packages:
            return {}

        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package;-50}\t${Version}\n',
                              '-W'] +
                             [pkg.name for pkg in packages],
                             stdout=subprocess.PIPE)
        # name -> (pkg, installed_version)
        pkgs_dict = dict((pkg.name, (pkg, PKG_NOT_INSTALLED))
                         for pkg in packages)
        try:
            for l in p.stdout:
                fields = l.split()
                if len(fields) == 2:
                    name = fields[0].decode('ascii')
                    status = fields[1].decode('ascii')
                    pkg, _ = pkgs_dict[name]
                    pkgs_dict[name] = pkg, status
        finally:
            p.wait()

        return pkgs_dict

    def update_script(self):
        return '%s update' % self.bin

    def install_script(self, packages):
        return '%s install -y %s' % (self.bin,
                                     ' '.join(pkg.name for pkg in packages))


class YumInstaller(object):
    """Installer for systems using RPM and Yum (Fedora, CentOS, Red-Hat).
    """
    @classmethod
    def install(cls, packages, assume_yes=False):
        options = []
        if assume_yes:
            options.append('-y')
        required_pkgs = set(pkg.name for pkg in packages)
        r = subprocess.call(['yum', 'install'] + options + list(required_pkgs))

        # Checks on packages
        pkgs_status = cls.get_packages_info(packages)
        for pkg, status in itervalues(pkgs_status):
            if status is not None:
                required_pkgs.discard(pkg.name)
        if required_pkgs:
            logging.error("Error: some packages could not be installed:%s",
                          ''.join("\n    %s" % pkg for pkg in required_pkgs))

        return r, pkgs_status

    @staticmethod
    def get_packages_info(packages):
        if not packages:
            return {}

        p = subprocess.Popen(['rpm', '-q'] +
                             [pkg.name for pkg in packages] +
                             ['--qf', '+%{NAME} %{VERSION}-%{RELEASE}\\n'],
                             stdout=subprocess.PIPE)
        # name -> {pkg, installed_version}
        pkgs_dict = dict((pkg.name, (pkg, PKG_NOT_INSTALLED))
                         for pkg in packages)
        try:
            for l in p.stdout:
                if l[0] == b'+':
                    fields = l[1:].split()
                    if len(fields) == 2:
                        name = fields[0].decode('ascii')
                        status = fields[1].decode('ascii')
                        pkg, _ = pkgs_dict[name]
                        pkgs_dict[name] = pkg, status
        finally:
            p.wait()

        return pkgs_dict

    @staticmethod
    def update_script():
        return ''

    @staticmethod
    def install_script(packages):
        return 'yum install -y %s' % ' '.join(pkg.name for pkg in packages)


def select_installer(pack, runs, target_distribution=THIS_DISTRIBUTION,
                     check_distrib_compat=True):
    """Selects the right package installer for a Linux distribution.
    """
    orig_distribution = runs[0]['distribution'][0].lower()

    # Checks that the distributions match
    if not check_distrib_compat:
        pass
    elif (set([orig_distribution, target_distribution]) ==
            set(['ubuntu', 'debian'])):
        # Packages are more or less the same on Debian and Ubuntu
        logging.warning("Installing on %s but pack was generated on %s",
                        target_distribution.capitalize(),
                        orig_distribution.capitalize())
    elif target_distribution is None:
        raise CantFindInstaller("Target distribution is unknown; try using "
                                "--distribution")
    elif orig_distribution != target_distribution:
        raise CantFindInstaller(
            "Installing on %s but pack was generated on %s" % (
                target_distribution.capitalize(),
                orig_distribution.capitalize()))

    # Selects installation method
    if target_distribution == 'ubuntu':
        installer = AptInstaller('apt-get')
    elif target_distribution == 'debian':
        # aptitude is not installed by default, so use apt-get here too
        installer = AptInstaller('apt-get')
    elif (target_distribution in ('centos', 'centos linux',
                                  'fedora', 'scientific linux') or
            target_distribution.startswith('red hat')):
        installer = YumInstaller()
    else:
        raise CantFindInstaller("This distribution, \"%s\", is not supported" %
                                target_distribution.capitalize())

    return installer
