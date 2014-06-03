from __future__ import unicode_literals

import logging
import os
import platform
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile

import reprounzip.common


THIS_DISTRIBUTION = platform.linux_distribution()[0].lower()


def shell_escape(s):
    if any(c in s for c in string.whitespace + '*$\\"\''):
        return '"%s"' % (s.replace('\\', '\\\\')
                          .replace('"', '\\"')
                          .replace('$', '\\$'))
    else:
        return s


def load_config(pack):
    tmp = tempfile.mkdtemp(prefix='reprozip_')
    try:
        # Loads info from package
        tar = tarfile.open(pack, 'r:*')
        f = tar.extractfile('METADATA/version')
        version = f.read()
        f.close()
        if version != b'REPROZIP VERSION 1\n':
            sys.stderr.write("Unknown pack format\n")
            sys.exit(1)
        tar.extract('METADATA/config.yml', path=tmp)
        tar.close()
        configfile = os.path.join(tmp, 'METADATA/config.yml')
        ret = reprounzip.common.load_config(configfile)
    finally:
        shutil.rmtree(tmp)

    return ret


class AptInstaller(object):
    def __init__(self, binary):
        self.bin = binary

    def install(self, packages, assume_yes=False):
        # Installs
        options = []
        if assume_yes:
            options.append('-y')
        returncode = subprocess.call([self.bin, 'install'] +
                                     options +
                                     [pkg.name for pkg in packages])
        if returncode != 0:
            return returncode

        # Checks package versions
        pkgs_dict = dict((pkg.name, pkg) for pkg in packages)
        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package;-50}\t${Version}\n',
                              '-W'] +
                             [pkg.name for pkg in packages],
                             stdout=subprocess.PIPE)
        try:
            for l in p.stdout:
                fields = l.split()
                if len(fields) == 2:
                    name = fields[0].decode('ascii')
                    pkg = pkgs_dict.pop(name)
                    version = fields[1].decode('ascii')
                    if pkg.version != version:
                        sys.stderr.write("Warning: version %s of %s was "
                                         "installed, instead of %s\n" % (
                                             version, name, pkg.version))
                    logging.info("Installed %s %s (original: %s)" % (
                                 name, version, pkg.version))
        finally:
            p.wait()
        if pkgs_dict:
            sys.stderr.write("Error: some packages could not be installed:\n")
            for pkg in pkgs_dict.keys():
                sys.stderr.write("    %s\n" % pkg)
        assert p.returncode == 0

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


def join_root(root, path):
    assert path[0] == '/'
    assert len(path) == 1 or path[1] != '/'
    return os.path.join(root, path[1:])
