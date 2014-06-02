from __future__ import unicode_literals

import os
import shutil
import sys

from reprounzip.unpackers.common import load_config, select_installer,\
    shell_escape
from reprounzip.utils import find_all_links


def rb_escape(s):
    return "'%s'" % (s.replace('\\', '\\\\')
                      .replace("'", "\\'"))


def select_box(runs):
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    if architecture not in ('i686', 'x86_64'):
        sys.stderr.write("Error: unsupported architecture %s\n" % architecture)

    # Ubuntu
    if distribution == 'ubuntu':
        if version != '12.04':
            sys.stderr.write("Warning: using Ubuntu 12.01 'Precise' instead "
                             "of '%s'\n" % version)
        if architecture == 'i686':
            return 'ubuntu', 'hashicorp/precise32'
        else:  # architecture == 'x86_64':
            return 'ubuntu', 'hashicorp/precise64'

    # Debian
    elif distribution != 'debian':
        sys.stderr.write("Warning: unsupported distribution %s, using Debian"
                         "\n" % distribution)
    if (distribution == 'debian' and
            version != '7' and not version.startswith('jessie')):
        sys.stderr.write("Warning: using Debian 7 'Jessie' instead of '%s'"
                         "\n" % version)
    if architecture == 'i686':
        return 'debian', 'remram/debian-7.5-i386'
    else:  # architecture == 'x86_64':
        return 'debian', 'remram/debian-7.5-amd64'


def create_vagrant(args):
    """Sets up the experiment to be run in a Vagrant-built virtual machine.

    This can either build a chroot or not.

    If building a chroot, we do just like without Vagrant: we copy all the
    files and only get what's missing from the host. But we do install
    automatically the packages whose files are required.

    If not building a chroot, we install all the packages, and only unpack
    files that don't come from packages.

    In short: files from packages with packfiles=True will only be used if
    building a chroot.
    """
    pack = args.pack[0]
    target = args.target[0]
    if os.path.exists(target):
        sys.stderr.write("Error: Target directory exists\n")
        sys.exit(1)
    use_chroot = args.use_chroot

    # Loads config
    runs, packages, other_files = load_config(pack)

    target_distribution, box = select_box(runs)

    # If using chroot, we might still need to install packages to get missing
    # (not packed) files
    if use_chroot:
        packages = [pkg for pkg in packages if not pkg.packfiles]
        if packages:
            sys.stderr.write("Warning: Some packages were not packed, so "
                             "we'll install and copy their files\n"
                             "Packages that are missing:\n%s\n" %
                             ' '.join(pkg.name for pkg in packages))

    if packages:
        installer = select_installer(pack, runs, target_distribution)

    os.mkdir(target)

    # Writes setup script
    with open(os.path.join(target, 'setup.sh'), 'w') as fp:
        fp.write('#!/bin/sh\n\n')
        if packages:
            # Updates package sources
            fp.write(installer.update_script())
            fp.write('\n')
            # Installs necessary packages
            fp.write(installer.install_script(packages))
            fp.write('\n\n')

            if use_chroot:
                for pkg in packages:
                    fp.write('# Copies files from package %s\n' % pkg.name)
                    for ff in pkg.files:
                        for f in find_all_links(ff.path):
                            dest = f
                            if dest[0] == '/':
                                dest = dest[1:]
                            dest = os.path.join('root', dest)
                            fp.write('cp %s %s\n' % (shell_escape(f),
                                                     shell_escape(dest)))
                    fp.write('\n')
            # TODO : Compare package versions (painful because of sh)

        # Untar
        if use_chroot:
            fp.write('mkdir /experimentroot; cd /experimentroot\n')
        else:
            fp.write('cd /\n')
        fp.write('tar zpxf /vagrant/experiment.rpz --strip=1 %s\n' % ' '.join(
                 shell_escape('DATA' + f.path) for f in other_files))

        # TODO : With chroot: need to copy /bin/sh + deps (ldd)

    # Copies pack
    shutil.copyfile(pack, os.path.join(target, 'experiment.rpz'))

    # Writes start script
    with open(os.path.join(target, 'script.sh'), 'w') as fp:
        fp.write('#!/bin/bash\n\n')
        for run in runs:
            cmd = 'cd %s && ' % shell_escape(run['workingdir'])
            # FIXME : Use exec -a or something if binary != argv[0]
            cmd += ' '.join(
                     shell_escape(a)
                     for a in [run['binary']] + run['argv'][1:])
            userspec = '%s:%s' % (run.get('uid', 1000), run.get('gid', 1000))
            fp.write('chroot --userspec=%s /experimentroot /bin/sh -c %s\n' % (
                     userspec,
                     shell_escape(cmd)))

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


def setup(subparsers, general_options):
    # Creates a virtual machine with Vagrant
    parser_vagrant = subparsers.add_parser(
            'vagrant', parents=[general_options],
            help="Unpacks the files and sets up the experiment to be run in "
            "Vagrant")
    parser_vagrant.add_argument('pack', nargs=1,
                                help="Pack to extract")
    parser_vagrant.add_argument('target', nargs=1,
                                help="Directory to create")
    parser_vagrant.add_argument(
            '--use-chroot', action='store_true',
            help="Use a chroot and the original files in the virtual machine")
    parser_vagrant.set_defaults(func=create_vagrant)
