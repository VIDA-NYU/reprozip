from __future__ import unicode_literals

import logging
import shutil
import sys
import tarfile
import tempfile
import os
import platform
import re
import sqlite3
import subprocess

from reprozip import _pytracer
import reprozip.tracer.common


def shell_escape(s):
    return '"%s"' % (s.replace('\\', '\\\\')
                      .replace('"', '\\"')
                      .replace('$', '\\$'))


def rb_escape(s):
    return "'%s'" % (s.replace('\\', '\\\\')
                      .replace("'", "\\'"))


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
            options.append('-y')
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

    def update_script(self):
        return '%s update' % self.bin

    def install_script(self, packages):
        return '%s install -y %s' % (self.bin,
                                     ' '.join(pkg.name for pkg in packages))


def identify_distribution(runs):
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
    return orig_distribution


def select_installer(pack, runs):
    # Identifies current distribution
    distribution = platform.linux_distribution()[0].lower()

    orig_distribution = identify_distribution(runs)

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

    return distribution.capitalize(), installer


def select_box(runs):
    orig_distribution = identify_distribution(runs)
    # TODO
    return 'hashicorp/precise32'


def installpkgs(args):
    pack = args.pack[0]

    # Loads config
    runs, packages, other_files = load_config(pack)

    distribution, installer = select_installer(pack, runs)

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

    # Copies /bin/sh + dependencies
    fmt = re.compile(r'^\t(?:[^ ]+ => )?([^ ]+) \([x0-9a-z]+\)$')
    p = subprocess.Popen(['ldd', '/bin/sh'], stdout=subprocess.PIPE)
    try:
        for l in p.stdout:
            l = l.decode('ascii')
            m = fmt.match(l)
            f = m.group(1)
            if not os.path.exists(f):
                continue
            dest = f
            if dest[0] == '/':
                dest = dest[1:]
            dest = os.path.join(root, dest)
            makedir(os.path.dirname(dest))
            shutil.copy(f, dest)
    finally:
        p.wait()
    assert p.returncode == 0
    makedir(os.path.join(root, 'bin'))
    shutil.copy('/bin/sh', os.path.join(root, 'bin/sh'))

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
                cmd += 'exec -a %s %s' % (
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

    print("Experiment set up, run %s to start" % (
          os.path.join(target, 'script.sh')))


def create_vagrant(args):
    pack = args.pack[0]
    target = args.target[0]
    if os.path.exists(target):
        sys.stderr.write("Error: Target directory exists\n")
        sys.exit(1)

    # Loads config
    runs, packages, other_files = load_config(pack)

    distribution, installer = select_installer(pack, runs)
    box = select_box(runs)

    os.mkdir(target)

    # Writes setup script
    with open(os.path.join(target, 'setup.sh'), 'w') as fp:
        fp.write('#!/bin/sh\n\n')
        # Makes sure the start script is executable
        fp.write('chmod +x script.sh\n\n')
        # Updates package sources
        fp.write(installer.update_script())
        fp.write('\n')
        # Installs necessary packages
        fp.write(installer.install_script(packages))
        fp.write('\n\n')
        # TODO : Compare package versions (painful because of sh)
        # Untar
        fp.write('cd /\n')
        fp.write('tar zxf /vagrant/experiment.rpz --exclude=METADATA\n')

    # Copies pack
    shutil.copyfile(pack, os.path.join(target, 'experiment.rpz'))

    # Writes start script
    with open(os.path.join(target, 'script.sh'), 'w') as fp:
        fp.write('#!/bin/sh\n\n')
        for run in runs:
            fp.write('cd %s\n' % shell_escape(run['workingdir']))
            if os.path.basename(run['binary']) != run['argv'][0]:
                fp.write('exec -a %s %s\n' % (
                        shell_escape(run['argv'][0]),
                        ' '.join(shell_escape(a)
                                 for a in [run['binary']] + run['argv'][1:])))
            else:
                fp.write('exec %s\n' % ' '.join(
                        shell_escape(a)
                        for a in [run['binary']] + run['argv'][1:]))
    # TODO : Copy /bin/sh over and use /bin/sh -c exec or no exec

    # Writes Vagrant file
    with open(os.path.join(target, 'Vagrantfile'), 'w') as fp:
        # Vagrant header and version
        fp.write('# -*- mode: ruby -*-\n'
                 '# vi: set ft=ruby\n\n'
                 'VAGRANTFILE_API_VERSION = "2"\n\n'
                 'Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|\n')
        # Selects which box to install
        fp.write('  config.vm.box = "%s"\n' % box)
        # Run the setup script on the virtual machine
        fp.write('  config.vm.provision "shell", path: "setup.sh"\n')

        fp.write('end\n')

    if not target:
        target_dir = './'
    elif target.endswith('/'):
        target_dir = target
    else:
        target_dir = target + '/'
    print("Vagrantfile ready\n"
          "Create the virtual machine by running 'vagrant up' from %s\n"
          "Then, ssh into it (for example using 'vagrant ssh') and run "
          "'sh script.sh'" % target_dir)


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

    # Creates a virtual machine with Vagrant
    parser_vagrant = subparsers.add_parser(
            'vagrant',
            help="Unpacks the files and sets up the experiment to be run in "
            "Vagrant")
    parser_vagrant.add_argument('pack', nargs=1,
                                help="Pack to extract")
    parser_vagrant.add_argument('target', nargs=1,
                                help="Directory to create")
    parser_vagrant.set_defaults(func=create_vagrant)
