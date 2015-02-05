# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Vagrant plugin for reprounzip.

This files contains the 'vagrant' unpacker, which builds a Vagrant template
from a reprozip pack. That template can then be run as a virtual machine via
Vagrant (``vagrant up``).

See http://www.vagrantup.com/
"""

from __future__ import unicode_literals

import argparse
import logging
import os
import paramiko
import pickle
from rpaths import PosixPath, Path
import scp
import subprocess
import sys
import tarfile

from reprounzip.common import load_config, record_usage
from reprounzip import signals
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_MAYBE, \
    CantFindInstaller, composite_action, target_must_exist, make_unique_name, \
    shell_escape, select_installer, busybox_url, join_root, \
    FileUploader, FileDownloader, get_runs
from reprounzip.unpackers.common.x11 import X11Handler
from reprounzip.unpackers.vagrant.run_command import IgnoreMissingKey, \
    run_interactive
from reprounzip.utils import unicode_, iteritems, check_output


def rb_escape(s):
    """Given bl'a, returns 'bl\\'a'.
    """
    return "'%s'" % (s.replace('\\', '\\\\')
                      .replace("'", "\\'"))


def select_box(runs):
    """Selects a box for the experiment, with the correct distribution.
    """
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    record_usage(vagrant_select_box='%s;%s;%s' % (distribution, version,
                                                  architecture))

    if architecture not in ('i686', 'x86_64'):
        logging.critical("Error: unsupported architecture %s", architecture)
        sys.exit(1)

    # Ubuntu
    if distribution == 'ubuntu':
        if version == '12.04':
            if architecture == 'i686':
                return 'ubuntu', 'hashicorp/precise32'
            else:  # architecture == 'x86_64'
                return 'ubuntu', 'hashicorp/precise64'
        if version != '14.04':
            logging.warning("using Ubuntu 14.04 'Trusty' instead of '%s'",
                            version)
        if architecture == 'i686':
            return 'ubuntu', 'ubuntu/trusty32'
        else:  # architecture == 'x86_64':
            return 'ubuntu', 'ubuntu/trusty64'

    # Debian
    else:
        if distribution != 'debian':
            logging.warning("unsupported distribution %s, using Debian",
                            distribution)
            version = '7'

        if (version != '7' and not version.startswith('7.') and
                not version.startswith('wheezy')):
            logging.warning("using Debian 7 'Wheezy' instead of '%s'", version)

        if architecture == 'i686':
            return 'debian', 'remram/debian-7-i386'
        else:  # architecture == 'x86_64':
            return 'debian', 'remram/debian-7-amd64'


def write_dict(filename, dct):
    to_write = {'unpacker': 'vagrant'}
    to_write.update(dct)
    with filename.open('wb') as fp:
        pickle.dump(to_write, fp, 2)


def read_dict(filename):
    with filename.open('rb') as fp:
        dct = pickle.load(fp)
    if dct['unpacker'] != 'vagrant':
        raise ValueError("Wrong unpacker used: %s != vagrant" %
                         dct['unpacker'])
    return dct


def get_ssh_parameters(target):
    """Reads the SSH parameters from ``vagrant ssh`` command output.
    """
    try:
        stdout = check_output(['vagrant', 'ssh-config'],
                              cwd=target.path,
                              stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # Makes sure the VM is running
        subprocess.check_call(['vagrant', 'up'],
                              cwd=target.path)
        # Try again
        stdout = check_output(['vagrant', 'ssh-config'],
                              cwd=target.path)

    info = {}
    for line in stdout.split(b'\n'):
        line = line.strip().split(b' ', 1)
        if len(line) != 2:
            continue
        info[line[0].decode('utf-8').lower()] = line[1].decode('utf-8')

    if 'identityfile' in info:
        key_file = info['identityfile']
    else:
        key_file = Path('~/.vagrant.d/insecure_private_key').expand_user()
    ret = dict(hostname=info.get('hostname', '127.0.0.1'),
               port=int(info.get('port', 2222)),
               username=info.get('user', 'vagrant'),
               key_filename=key_file)
    logging.debug("SSH parameters from Vagrant: %s@%s:%s, key=%s",
                  ret['username'], ret['hostname'], ret['port'],
                  ret['key_filename'])
    return ret


def vagrant_setup_create(args):
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
    if not args.pack:
        logging.critical("setup/create needs the pack filename")
        sys.exit(1)

    pack = Path(args.pack[0])
    target = Path(args.target[0])
    if target.exists():
        logging.critical("Target directory exists")
        sys.exit(1)
    use_chroot = args.use_chroot
    mount_bind = args.bind_magic_dirs
    record_usage(use_chroot=use_chroot,
                 mount_bind=mount_bind)

    signals.pre_setup(target=target, pack=pack)

    # Unpacks configuration file
    tar = tarfile.open(str(pack), 'r:*')
    member = tar.getmember('METADATA/config.yml')
    member.name = 'config.yml'
    tar.extract(member, str(target))
    tar.close()

    # Loads config
    runs, packages, other_files = load_config(target / 'config.yml', True)

    if args.base_image and args.base_image[0]:
        record_usage(vagrant_explicit_image=True)
        box = args.base_image[0]
        if args.distribution:
            target_distribution = args.distribution[0]
        else:
            target_distribution = None
    else:
        target_distribution, box = select_box(runs)
    logging.info("Using box %s", box)
    logging.debug("Distribution: %s", target_distribution or "unknown")

    # If using chroot, we might still need to install packages to get missing
    # (not packed) files
    if use_chroot:
        packages = [pkg for pkg in packages if not pkg.packfiles]
        if packages:
            record_usage(vagrant_install_pkgs=True)
            logging.info("Some packages were not packed, so we'll install and "
                         "copy their files\n"
                         "Packages that are missing:\n%s",
                         ' '.join(pkg.name for pkg in packages))

    if packages:
        try:
            installer = select_installer(pack, runs, target_distribution)
        except CantFindInstaller as e:
            logging.error("Need to install %d packages but couldn't select a "
                          "package installer: %s",
                          len(packages), e)

    target.mkdir(parents=True)

    # Writes setup script
    logging.info("Writing setup script %s...", target / 'setup.sh')
    with (target / 'setup.sh').open('w', encoding='utf-8', newline='\n') as fp:
        fp.write('#!/bin/sh\n\nset -e\n\n')
        if packages:
            # Updates package sources
            fp.write(installer.update_script())
            fp.write('\n')
            # Installs necessary packages
            fp.write(installer.install_script(packages))
            fp.write('\n')
            # TODO : Compare package versions (painful because of sh)

        # Untar
        if use_chroot:
            fp.write('\n'
                     'mkdir /experimentroot; cd /experimentroot\n')
            fp.write('tar zpxf /vagrant/experiment.rpz '
                     '--numeric-owner --strip=1 DATA\n')
            if mount_bind:
                fp.write('\n'
                         'mkdir -p /experimentroot/dev\n'
                         'mount -o rbind /dev /experimentroot/dev\n'
                         'mkdir -p /experimentroot/proc\n'
                         'mount -o rbind /proc /experimentroot/proc\n')

            for pkg in packages:
                fp.write('\n# Copies files from package %s\n' % pkg.name)
                for f in pkg.files:
                    f = f.path
                    dest = join_root(PosixPath('/experimentroot'), f)
                    fp.write('mkdir -p %s\n' %
                             shell_escape(unicode_(f.parent)))
                    fp.write('cp -L %s %s\n' % (
                             shell_escape(unicode_(f)),
                             shell_escape(unicode_(dest))))
        else:
            fp.write('\ncd /\n')
            paths = set()
            pathlist = []
            dataroot = PosixPath('DATA')
            # Adds intermediate directories, and checks for existence in the
            # tar
            tar = tarfile.open(str(pack), 'r:*')
            for f in other_files:
                path = PosixPath('/')
                for c in f.path.components[1:]:
                    path = path / c
                    if path in paths:
                        continue
                    paths.add(path)
                    datapath = join_root(dataroot, path)
                    try:
                        tar.getmember(str(datapath))
                    except KeyError:
                        logging.info("Missing file %s", datapath)
                    else:
                        pathlist.append(unicode_(datapath))
            tar.close()
            # FIXME : for some reason we need reversed() here, I'm not sure
            # why. Need to read more of tar's docs.
            # TAR bug: --no-overwrite-dir removes --keep-old-files
            fp.write('tar zpxf /vagrant/experiment.rpz --keep-old-files '
                     '--numeric-owner --strip=1 %s\n' %
                     ' '.join(shell_escape(p) for p in reversed(pathlist)))

        # Copies /bin/sh + dependencies
        if use_chroot:
            url = busybox_url(runs[0]['architecture'])
            fp.write(r'''
mkdir -p /experimentroot/bin
mkdir -p /experimentroot/usr/bin
if [ ! -e /experimentroot/bin/sh -o ! -e /experimentroot/usr/bin/env ]; then
    wget --quiet -O /experimentroot/bin/busybox {url}
    chmod +x /experimentroot/bin/busybox
fi
[ -e /experimentroot/bin/sh ] || \
    ln -s /bin/busybox /experimentroot/bin/sh
[ -e /experimentroot/usr/bin/env ] || \
    ln -s /bin/busybox /experimentroot/usr/bin/env
'''.format(url=url))

    # Copies pack
    logging.info("Copying pack file...")
    pack.copyfile(target / 'experiment.rpz')

    # Writes Vagrant file
    logging.info("Writing %s...", target / 'Vagrantfile')
    with (target / 'Vagrantfile').open('w', encoding='utf-8',
                                       newline='\n') as fp:
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

    # Meta-data for reprounzip
    write_dict(target / '.reprounzip', {'use_chroot': use_chroot})

    signals.post_setup(target=target)


@target_must_exist
def vagrant_setup_start(args):
    """Starts the vagrant-built virtual machine.
    """
    target = Path(args.target[0])
    read_dict(target / '.reprounzip')

    logging.info("Calling 'vagrant up'...")
    try:
        retcode = subprocess.call(['vagrant', 'up'], cwd=target.path)
    except OSError:
        logging.critical("vagrant executable not found")
        sys.exit(1)
    else:
        if retcode != 0:
            logging.critical("vagrant up failed with code %d", retcode)
            sys.exit(1)


@target_must_exist
def vagrant_run(args):
    """Runs the experiment in the virtual machine.
    """
    target = Path(args.target[0])
    use_chroot = read_dict(target / '.reprounzip').get('use_chroot', True)
    cmdline = args.cmdline

    # Loads config
    runs, packages, other_files = load_config(target / 'config.yml', True)

    selected_runs = get_runs(runs, args.run, cmdline)

    hostname = runs[selected_runs[0]].get('hostname', 'reprounzip')

    # X11 handler
    x11 = X11Handler(args.x11, ('local', hostname), args.x11_display)

    cmds = []
    for run_number in selected_runs:
        run = runs[run_number]
        cmd = 'cd %s && ' % shell_escape(run['workingdir'])
        cmd += '/usr/bin/env -i '
        environ = x11.fix_env(run['environ'])
        cmd += ' '.join('%s=%s' % (k, shell_escape(v))
                        for k, v in iteritems(environ))
        cmd += ' '
        # FIXME : Use exec -a or something if binary != argv[0]
        if cmdline is None:
            argv = [run['binary']] + run['argv'][1:]
        else:
            argv = cmdline
        cmd += ' '.join(shell_escape(a) for a in argv)
        uid = run.get('uid', 1000)
        gid = run.get('gid', 1000)
        if use_chroot:
            userspec = '%s:%s' % (uid, gid)
            cmd = ('chroot --userspec=%s /experimentroot '
                   '/bin/sh -c %s' % (
                       userspec,
                       shell_escape(cmd)))
        else:
            cmd = 'sudo -u \'#%d\' sh -c %s' % (uid, shell_escape(cmd))
        cmds.append(cmd)
    if use_chroot:
        cmds = ['chroot /experimentroot /bin/sh -c %s' % shell_escape(c)
                for c in x11.init_cmds] + cmds
    else:
        cmds = x11.init_cmds + cmds
    cmds = ' && '.join(cmds)
    # Sets the hostname to the original experiment's machine's
    # FIXME: not reentrant: this restores the Vagrant machine's hostname after
    # the run, which might cause issues if several "reprounzip vagrant run" are
    # running at once
    cmds = ('OLD_HOSTNAME=$(/bin/hostname); /bin/hostname %s; ' % hostname +
            cmds +
            '; RES=$?; /bin/hostname "$OLD_HOSTNAME"; exit $RES')
    cmds = '/usr/bin/sudo /bin/sh -c %s' % shell_escape(cmds)

    # Gets vagrant SSH parameters
    info = get_ssh_parameters(target)

    signals.pre_run(target=target)

    interactive = not (args.no_stdin or
                       os.environ.get('REPROUNZIP_NON_INTERACTIVE'))
    retcode = run_interactive(info, interactive,
                              cmds,
                              not args.no_pty,
                              x11.port_forward)
    sys.stderr.write("\r\n*** Command finished, status: %d\r\n" %
                     retcode)

    signals.post_run(target=target, retcode=retcode)


class SSHUploader(FileUploader):
    def __init__(self, target, input_files, files, use_chroot):
        self.use_chroot = use_chroot
        FileUploader.__init__(self, target, input_files, files)

    def prepare_upload(self, files):
        # Checks whether the VM is running
        try:
            ssh_info = get_ssh_parameters(self.target)
        except subprocess.CalledProcessError:
            logging.critical("Failed to get the status of the machine -- is "
                             "it running?")
            sys.exit(1)

        # Connect with scp
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(IgnoreMissingKey())
        self.ssh.connect(**ssh_info)
        self.client_scp = scp.SCPClient(self.ssh.get_transport())

    def upload_file(self, local_path, input_path):
        if self.use_chroot:
            remote_path = join_root(PosixPath('/experimentroot'),
                                    PosixPath(input_path))
        else:
            remote_path = input_path

        # Upload to a temporary file first
        logging.info("Uploading file via SCP...")
        rtemp = PosixPath(make_unique_name(b'/tmp/reprozip_input_'))
        self.client_scp.put(local_path.path, rtemp.path, recursive=False)

        # Move it
        logging.info("Moving file into place...")
        chan = self.ssh.get_transport().open_session()
        chown_cmd = '/bin/chown --reference=%s %s' % (
                shell_escape(remote_path.path),
                shell_escape(rtemp.path))
        chmod_cmd = '/bin/chmod --reference=%s %s' % (
                shell_escape(remote_path.path),
                shell_escape(rtemp.path))
        mv_cmd = '/bin/mv %s %s' % (
                shell_escape(rtemp.path),
                shell_escape(remote_path.path))
        chan.exec_command('/usr/bin/sudo /bin/sh -c %s' % shell_escape(
                          ';'.join((chown_cmd, chmod_cmd, mv_cmd))))
        if chan.recv_exit_status() != 0:
            logging.critical("Couldn't move file in virtual machine")
            sys.exit(1)
        chan.close()

    def finalize(self):
        self.ssh.close()


@target_must_exist
def vagrant_upload(args):
    """Replaces an input file in the VM.
    """
    target = Path(args.target[0])
    files = args.file
    unpacked_info = read_dict(target / '.reprounzip')
    input_files = unpacked_info.setdefault('input_files', {})
    use_chroot = unpacked_info['use_chroot']

    try:
        SSHUploader(target, input_files, files, use_chroot)
    finally:
        write_dict(target / '.reprounzip', unpacked_info)


class SSHDownloader(FileDownloader):
    def __init__(self, target, files, use_chroot):
        self.use_chroot = use_chroot
        FileDownloader.__init__(self, target, files)

    def prepare_download(self, files):
        # Checks whether the VM is running
        try:
            info = get_ssh_parameters(self.target)
        except subprocess.CalledProcessError:
            logging.critical("Failed to get the status of the machine -- is "
                             "it running?")
            sys.exit(1)

        # Connect with scp
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(IgnoreMissingKey())
        self.ssh.connect(**info)
        self.client_scp = scp.SCPClient(self.ssh.get_transport())

    def download(self, remote_path, local_path):
        if self.use_chroot:
            remote_path = join_root(PosixPath('/experimentroot'), remote_path)
        try:
            self.client_scp.get(remote_path.path, local_path.path,
                                recursive=False)
        except scp.SCPException as e:
            logging.critical("Couldn't download output file: %s\n%s",
                             remote_path, str(e))
            sys.exit(1)

    def finalize(self):
        self.ssh.close()


@target_must_exist
def vagrant_download(args):
    """Gets an output file out of the VM.
    """
    target = Path(args.target[0])
    files = args.file
    use_chroot = read_dict(target / '.reprounzip')['use_chroot']

    SSHDownloader(target, files, use_chroot)


@target_must_exist
def vagrant_destroy_vm(args):
    """Destroys the VM through Vagrant.
    """
    target = Path(args.target[0])
    read_dict(target / '.reprounzip')

    retcode = subprocess.call(['vagrant', 'destroy', '-f'], cwd=target.path)
    if retcode != 0:
        logging.critical("vagrant destroy failed with code %d, ignoring...",
                         retcode)


@target_must_exist
def vagrant_destroy_dir(args):
    """Destroys the directory.
    """
    target = Path(args.target[0])
    read_dict(target / '.reprounzip')

    signals.pre_destroy(target=target)
    target.rmtree()
    signals.post_destroy(target=target)


def test_has_vagrant(pack, **kwargs):
    """Compatibility test: has vagrant (ok) or not (maybe).
    """
    pathlist = os.environ['PATH'].split(os.pathsep) + ['.']
    pathexts = os.environ.get('PATHEXT', '').split(os.pathsep)
    for path in pathlist:
        for ext in pathexts:
            fullpath = os.path.join(path, 'vagrant') + ext
            if os.path.isfile(fullpath):
                return COMPAT_OK
    return COMPAT_MAYBE, "vagrant not found in PATH"


def setup(parser, **kwargs):
    """Runs the experiment in a virtual machine created through Vagrant

    You will need Vagrant to be installed on your machine if you want to run
    the experiment.

    setup   setup/create    creates Vagrantfile (needs the pack filename)
            setup/start     starts or resume the virtual machine
    upload                  replaces input files in the machine
                            (without arguments, lists input files)
    run                     runs the experiment in the virtual machine
    suspend                 suspend the virtual machine without destroying it
    download                gets output files from the machine
                            (without arguments, lists output files)
    destroy destroy/vm      destroys the virtual machine
            destroy/dir     removes the unpacked directory

    For example:

        $ reprounzip vagrant setup mypack.rpz experiment; cd experiment
        $ reprounzip vagrant run .
        $ reprounzip vagrant download . results:/home/user/theresults.txt
        $ cd ..; reprounzip vagrant destroy experiment

    Upload specifications are either:
      :input_id             restores the original input file from the pack
      filename:input_id     replaces the input file with the specified local
                            file

    Download specifications are either:
      output_id:            print the output file to stdout
      output_id:filename    extracts the output file to the corresponding local
                            path
    """
    subparsers = parser.add_subparsers(title="actions",
                                       metavar='', help=argparse.SUPPRESS)
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('target', nargs=1, help="Experiment directory")

    # setup/create
    opt_setup = argparse.ArgumentParser(add_help=False)
    opt_setup.add_argument('pack', nargs=1, help="Pack to extract")
    opt_setup.add_argument(
            '--use-chroot', action='store_true',
            default=True,
            help=argparse.SUPPRESS)
    opt_setup.add_argument(
            '--dont-use-chroot', action='store_false', dest='use_chroot',
            default=True,
            help=("Don't prefer original files nor use chroot in the virtual "
                  "machine"))
    opt_setup.add_argument(
            '--no-use-chroot', action='store_false', dest='use_chroot',
            default=True, help=argparse.SUPPRESS)
    opt_setup.add_argument(
            '--dont-bind-magic-dirs', action='store_false', default=True,
            dest='bind_magic_dirs',
            help="Don't mount /dev and /proc inside the chroot (no effect if "
            "--dont-use-chroot is set)")
    opt_setup.add_argument('--base-image', nargs=1, help="Vagrant box to use")
    opt_setup.add_argument('--distribution', nargs=1,
                           help=("Distribution used in the Vagrant box (for "
                                 "package installer selection)"))
    parser_setup_create = subparsers.add_parser('setup/create',
                                                parents=[opt_setup, options])
    parser_setup_create.set_defaults(func=vagrant_setup_create)

    # setup/start
    parser_setup_start = subparsers.add_parser('setup/start',
                                               parents=[options])
    parser_setup_start.set_defaults(func=vagrant_setup_start)

    # setup
    parser_setup = subparsers.add_parser('setup', parents=[opt_setup, options])
    parser_setup.set_defaults(func=composite_action(vagrant_setup_create,
                                                    vagrant_setup_start))

    # upload
    parser_upload = subparsers.add_parser('upload', parents=[options])
    parser_upload.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                               help="<path>:<input_file_name")
    parser_upload.set_defaults(func=vagrant_upload)

    # run
    parser_run = subparsers.add_parser('run', parents=[options])
    parser_run.add_argument('run', default=None, nargs='?')
    parser_run.add_argument('--no-stdin', action='store_true', default=False,
                            help=("Don't connect program's input stream to "
                                  "this terminal"))
    parser_run.add_argument('--no-pty', action='store_true', default=False,
                            help="Don't request a PTY from the SSH server")
    parser_run.add_argument('--cmdline', nargs=argparse.REMAINDER,
                            help="Command line to run")
    parser_run.add_argument('--enable-x11', action='store_true', default=False,
                            dest='x11',
                            help=("Enable X11 support (needs an X server on "
                                  "the host)"))
    parser_run.add_argument('--x11-display', dest='x11_display',
                            help=("Display number to use on the experiment "
                                  "side (change the host display with the "
                                  "DISPLAY environment variable)"))
    parser_run.set_defaults(func=vagrant_run)

    # download
    parser_download = subparsers.add_parser('download', parents=[options])
    parser_download.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                                 help="<output_file_name>:<path>")
    parser_download.set_defaults(func=vagrant_download)

    # destroy/vm
    parser_destroy_vm = subparsers.add_parser('destroy/vm',
                                              parents=[options])
    parser_destroy_vm.set_defaults(func=vagrant_destroy_vm)

    # destroy/dir
    parser_destroy_dir = subparsers.add_parser('destroy/dir',
                                               parents=[options])
    parser_destroy_dir.set_defaults(func=vagrant_destroy_dir)

    # destroy
    parser_destroy = subparsers.add_parser('destroy', parents=[options])
    parser_destroy.set_defaults(func=composite_action(vagrant_destroy_vm,
                                                      vagrant_destroy_dir))

    return {'test_compatibility': test_has_vagrant}
