# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions for unpacker plugins.

This contains functions related to shell scripts, package managers, and the
pack files.
"""

from __future__ import unicode_literals

import platform
from rpaths import Path
import string
import subprocess
import sys
import tarfile

import reprounzip.common


THIS_DISTRIBUTION = platform.linux_distribution()[0].lower()


PKG_NOT_INSTALLED = "(not installed)"


def shell_escape(s):
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if any(c in s for c in string.whitespace + '*$\\"\''):
        return '"%s"' % (s.replace('\\', '\\\\')
                          .replace('"', '\\"')
                          .replace('$', '\\$'))
    else:
        return s


def load_config(pack):
    tmp = Path.tempdir(prefix='reprozip_')
    try:
        # Loads info from package
        tar = tarfile.open(str(pack), 'r:*')
        f = tar.extractfile('METADATA/version')
        version = f.read()
        f.close()
        if version != b'REPROZIP VERSION 1\n':
            sys.stderr.write("Unknown pack format\n")
            sys.exit(1)
        tar.extract('METADATA/config.yml', path=str(tmp))
        tar.close()
        configfile = tmp / 'METADATA/config.yml'
        ret = reprounzip.common.load_config(configfile, canonical=True)
    finally:
        tmp.rmtree()

    return ret


class AptInstaller(object):
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
        for pkg, status in pkgs_status.itervalues():
            if status is not None:
                required_pkgs.discard(pkg.name)
        if required_pkgs:
            sys.stderr.write("Error: some packages could not be installed:\n")
            for pkg in required_pkgs:
                sys.stderr.write("    %s\n" % pkg)

        return r, pkgs_status

    def get_packages_info(self, packages):
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
                else:
                    name = fields[0].decode('ascii')
                    status = PKG_NOT_INSTALLED
                pkg, _s = pkgs_dict[name]
                pkgs_dict[name] = pkg, status
        finally:
            p.wait()

        return pkgs_dict

    def update_script(self):
        return '%s update' % self.bin

    def install_script(self, packages):
        return '%s install -y %s' % (self.bin,
                                     ' '.join(pkg.name for pkg in packages))


def select_installer(pack, runs, target_distribution=THIS_DISTRIBUTION):
    orig_distribution = runs[0]['distribution'][0].lower()

    # Checks that the distributions match
    if (set([orig_distribution, target_distribution]) ==
            set(['ubuntu', 'debian'])):
        # Packages are more or less the same on Debian and Ubuntu
        sys.stderr.write("Warning: Installing on %s but pack was generated on "
                         "%s\n" % (
                             target_distribution.capitalize(),
                             orig_distribution.capitalize()))
    elif orig_distribution != target_distribution:
        sys.stderr.write("Error: Installing on %s but pack was generated on %s"
                         "\n" % (
                             target_distribution.capitalize(),
                             orig_distribution.capitalize()))
        sys.exit(1)

    # Selects installation method
    if target_distribution == 'ubuntu':
        installer = AptInstaller('apt-get')
    elif target_distribution == 'debian':
        installer = AptInstaller('aptitude')
    else:
        sys.stderr.write("Your current distribution, \"%s\", is not "
                         "supported\n" % target_distribution.capitalize())
        sys.exit(1)

    return installer


def busybox_url(arch):
    return 'http://www.busybox.net/downloads/binaries/latest/busybox-%s' % arch


def join_root(root, path):
    p_root, p_loc = path.split_root()
    assert p_root == b'/'
    return root / p_loc
