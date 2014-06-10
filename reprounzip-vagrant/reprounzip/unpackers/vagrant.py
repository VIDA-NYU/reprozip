from __future__ import unicode_literals

from rpaths import PosixPath, Path
import sys

from reprounzip.unpackers.common import load_config, select_installer,\
    shell_escape, join_root


def rb_escape(s):
    return "'%s'" % (s.replace('\\', '\\\\')
                      .replace("'", "\\'"))


def select_box(runs):
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    if architecture not in ('i686', 'x86_64'):
        sys.stderr.write("Error: unsupported architecture %s\n" % architecture)
        sys.exit(1)

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
    pack = Path(args.pack[0])
    target = Path(args.target[0])
    if target.exists():
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

    target.mkdir(parents=True)

    # Writes setup script
    with (target / 'setup.sh').open('w') as fp:
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
                    for f in pkg.files:
                        dest = join_root(PosixPath('root'), f)
                        fp.write('cp -L %s %s\n' % (
                                 shell_escape(unicode(f)),
                                 shell_escape(unicode(dest))))
                    fp.write('\n')
            # TODO : Compare package versions (painful because of sh)

        # Untar
        if use_chroot:
            fp.write('mkdir /experimentroot; cd /experimentroot\n')
            fp.write('tar zpxf /vagrant/experiment.rpz '
                     '--numeric-owner --strip=1 DATA\n')
        else:
            fp.write('cd /\n')
            paths = set()
            pathlist = []
            dataroot = PosixPath('DATA')
            for f in other_files:
                path = PosixPath('/')
                for c in f.path.components[1:]:
                    path = path / c
                    if path in paths:
                        continue
                    paths.add(path)
                    pathlist.append(unicode(join_root(dataroot, path)))
            fp.write('tar zpxf /vagrant/experiment.rpz '
                     '--numeric-owner --strip=1 %s\n' %
                     ' '.join(shell_escape(p) for p in pathlist))

        # Copies /bin/sh + dependencies
        if use_chroot:
            regex = r'^\t(?:[^ ]+ => )?([^ ]+) \([x0-9a-z]+\)$'
            fp.write(r'''
for i in $(ldd /bin/sh | perl -n -e '/{regex}/ && print "$1\n"'); do
    if [ -e "$i" ] ; then
        mkdir -p "$(dirname /experimentroot/$i)"
        cp -L "$i" "/experimentroot/$i"
    fi
done
mkdir -p /experimentroot/bin
cp -L /bin/sh /experimentroot/bin/sh
'''.format(regex=regex))

    # Copies pack
    pack.copyfile(target / 'experiment.rpz')

    # Writes start script
    with (target / 'script.sh').open('w') as fp:
        fp.write('#!/bin/bash\n\n')
        for run in runs:
            cmd = 'cd %s && ' % shell_escape(run['workingdir'])
            cmd += ' '.join('%s=%s' % (k, shell_escape(v))
                            for k, v in run['environ'].items())
            cmd += ' '
            # FIXME : Use exec -a or something if binary != argv[0]
            cmd += ' '.join(
                     shell_escape(a)
                     for a in [run['binary']] + run['argv'][1:])
            uid = run.get('uid', 1000)
            gid = run.get('gid', 1000)
            if use_chroot:
                userspec = '%s:%s' % (uid, gid)
                fp.write('sudo chroot --userspec=%s /experimentroot '
                         '/bin/sh -c %s\n' % (
                             userspec,
                             shell_escape(cmd)))
            else:
                fp.write('sudo -u \'#%d\' %s\n' % (
                         uid, cmd))

    # Writes Vagrant file
    with (target / 'Vagrantfile').open('w') as fp:
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

    target_readable = unicode(target)
    if not target_readable.endswith('/'):
        target_readable = target_readable + '/'
    print("Vagrantfile ready\n"
          "Create the virtual machine by running 'vagrant up' from %s\n"
          "Then, ssh into it (for example using 'vagrant ssh') and run "
          "'sh /vagrant/script.sh'" % target_readable)


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
