from __future__ import unicode_literals

import logging
import shutil
import sys
import tarfile
import tempfile
import os
import platform
import sqlite3
import subprocess

from reprozip import _pytracer
import reprozip.tracer.common


def shell_escape(s):
    return '"%s"' % (s.replace('\\', '\\\\')
                      .replace('"', '\\"')
                      .replace('$', '\\$'))


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
        ret = reprozip.tracer.common.load_config(configfile)
    finally:
        shutil.rmtree(tmp)

    return ret


def list_directories(pack):
    tmp = tempfile.mkdtemp(prefix='reprozip_')
    try:
        tar = tarfile.open(pack, 'r:*')
        tar.extract('METADATA/trace.sqlite3', path=tmp)
        database = os.path.join(tmp, 'METADATA/trace.sqlite3')
        tar.close()
        conn = sqlite3.connect(database)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        executed_files = cur.execute('''
                SELECT name
                FROM opened_files
                WHERE mode = ?
                ''',
                (_pytracer.FILE_WDIR,))
        result = set(n for (n,) in executed_files)
        cur.close()
        conn.close()
        return result
    finally:
        shutil.rmtree(tmp)


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
    pack = args.pack[0]

    # Loads config
    runs, packages, other_files = load_config(pack)

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


def makedir(path):
    if not os.path.exists(path):
        makedir(os.path.dirname(path))
        try:
            os.mkdir(path)
        except OSError:
            pass


def create_chroot(args):
    pack = args.pack[0]
    target = args.target[0]
    if os.path.exists(target):
        sys.stderr.write("Error: Target directory exists\n")
        sys.exit(1)

    # Loads config
    runs, packages, other_files = load_config(pack)

    os.mkdir(target)
    root = os.path.abspath(os.path.join(target, 'root'))
    os.mkdir(root)

    # Unpacks files
    tar = tarfile.open(pack, 'r:*')
    members = filter(lambda m: not m.name.startswith('METADATA/'),
                     tar.getmembers())
    tar.extractall(root, members)

    # Copies additional files
    # FIXME : This is because we need /bin/sh
    for d in ('/bin', '/lib/i386-linux-gnu'):
        path = root
        for c in d.split('/')[1:]:
            path = os.path.join(path, c)
            if not os.path.isdir(path):
                os.mkdir(path)
    for f in ('/bin/sh', '/lib/ld-linux.so.2', '/lib/i386-linux-gnu/libc.so.6'):
        dest = os.path.join(root, f.lstrip('/'))
        if not os.path.exists(dest):
            shutil.copy(f, dest)

    # Makes sure all the directories used as working directories exist
    # (they already do if files from them are used, but empty directories do
    # not get packed inside a tar archive)
    for directory in list_directories(pack):
        makedir(os.path.join(root, directory[1:]))

    # Writes start script
    with open(os.path.join(target, 'script.sh'), 'w') as fp:
        fp.write('#!/bin/sh\n\n')
        for run in runs:
            cmd = "cd %s && " % shell_escape(run['workingdir'])
            if os.path.basename(run['binary']) != run['argv'][0]:
                cmd += "exec -a %s %s" % (
                        shell_escape(run['argv'][0]),
                        ' '.join(shell_escape(a)
                                 for a in [run['binary']] + run['argv'][1:]))
            else:
                cmd += 'exec %s' % ' '.join(
                        shell_escape(a)
                        for a in [run['binary']] + run['argv'][1:])
            fp.write('chroot --userspec=1000 %s /bin/sh -c %s\n' % (
                    shell_escape(root),
                    shell_escape(cmd)))


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

    # Unpacks all the file so the experiment can be run with chroot
    parser_chroot = subparsers.add_parser(
            'chroot',
            help="Unpacks the files so the experiment can be run with chroot")
    parser_chroot.add_argument('pack', nargs=1,
                                    help="Pack to extract")
    parser_chroot.add_argument('target', nargs=1,
                                    help="Directory to create")
    parser_chroot.set_defaults(func=create_chroot)
