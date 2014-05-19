from __future__ import unicode_literals

import logging
import shutil
import sys
import tarfile
import tempfile
import os
import platform
import subprocess

from reprozip.tracer.common import load_config


UNPACKERS = {
    'executable'}


class AptInstaller(object):
    def __init__(self, binary):
        self.bin = binary

    def install(self, packages, assume_yes=False):
        # Installs
        options = []
        if assume_yes:
            options.append('y')
        returncode = subprocess.call([self.bin, 'install'] +
                                     options +
                                     [pkg.name for pkg in packages])
        if returncode != 0:
            return returncode

        # Checks package versions
        pkgs_dict = dict((pkg.name, pkg) for pkg in packages)
        p = subprocess.Popen(['dpkg-query',
                              '--showformat=${Package;-50}\t'
                                  '${Version}\n',
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


def installpkgs(args):
    pkg = args.pack[0]
    tmp = tempfile.mkdtemp(prefix='reprozip_')
    try:
        # Loads info from package
        tar = tarfile.open(pkg, 'r:*')
        f = tar.extractfile('METADATA/version')
        version = f.read()
        f.close()
        if version != b'REPROZIP VERSION 1\n':
            sys.stderr.write("Unknown pack format\n")
            print repr(version)
            sys.exit(1)
        tar.extract('METADATA/config.yml', path=tmp)
        configfile = os.path.join(tmp, 'METADATA/config.yml')
        runs, packages, other_files = load_config(configfile)
    finally:
        shutil.rmtree(tmp)

    # Identifies current distribution
    distribution = platform.linux_distribution()[0].lower()

    # Identifies original distribution
    orig_distribution = set(run['distribution'][0].lower() for run in runs)
    if len(orig_distribution) > 1:
        sys.stderr.write("Error: Multiple distributions were used in "
                         "generating the original pack\nThis is very "
                         "unusual\n")
        sys.exit(1)
    if not orig_distribution:
        sys.stderr.write("Error: No run in pack configuration. What is going "
                         "on?\n")
        sys.exit(1)
    orig_distribution, = orig_distribution

    # Checks that the distributions match
    print repr(set([orig_distribution, distribution]))
    if set([orig_distribution, distribution]) == set(['ubuntu', 'debian']):
        # Packages are more or less the same on Debian and Ubuntu
        sys.stderr.write("Warning: Installing on %s but pack was generated on "
                         "%s\n" % (
                         distribution.capitalize(),
                         orig_distribution.capitalize()))
    elif orig_distribution != distribution:
        sys.stderr.write("Error: Installing on %s but pack was generated on %s"
                         "\n" % (
                         distribution.capitalize(),
                         orig_distribution.capitalize()))
        sys.exit(1)

    # Selects installation method
    if distribution == 'ubuntu':
        installer = AptInstaller('apt-get')
    elif distribution == 'debian':
        installer = AptInstaller('aptitude')
    else:
        sys.stderr.write("Your current distribution, \"%s\", is not "
                         "supported\n" % distribution.capitalize())
        sys.exit(1)

    # Installs packages
    r = installer.install(packages, assume_yes=args.assume_yes)
    if r != 0:
        sys.exit(r)


def setup_unpack_subcommand(parser_unpack):
    subparsers = parser_unpack.add_subparsers(title="formats", metavar='')

    # Install the required packages
    parser_installpkgs = subparsers.add_parser(
            'installpkgs',
            help="Installs the required packages on this system")
    parser_installpkgs.add_argument('pack', nargs=1,
                                    help="Pack to process")
    parser_installpkgs.add_argument(
            '-y', '--assume-yes',
            help="Assumes yes for package manager's questions (if supported)")
    parser_installpkgs.set_defaults(func=installpkgs)
