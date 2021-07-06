# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Docker plugin for reprounzip.

This files contains the 'docker' unpacker, which builds a Dockerfile from a
reprozip pack. You can then build a container and run it with Docker.

See http://www.docker.io/
"""

from __future__ import division, print_function, unicode_literals

import argparse
from itertools import chain
import json
import logging
import os
import re
from rpaths import Path, PosixPath
import socket
import subprocess
import sys
import tarfile

from reprounzip.common import load_config, record_usage, RPZPack
from reprounzip import signals
from reprounzip.parameters import get_parameter
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_MAYBE, \
    UsageError, CantFindInstaller, composite_action, target_must_exist, \
    make_unique_name, shell_escape, select_installer, busybox_url, sudo_url, \
    rpztar_url, \
    FileUploader, FileDownloader, get_runs, add_environment_options, \
    fixup_environment, interruptible_call, metadata_read, metadata_write, \
    metadata_initial_iofiles, metadata_update_run, parse_ports
from reprounzip.unpackers.common.x11 import X11Handler, LocalForwarder
from reprounzip.utils import unicode_, iteritems, stderr, join_root, \
    download_file


logger = logging.getLogger('reprounzip.docker')


# How this all works:
#  - setup/create just copies file to the target directory and writes the
#    Dockerfile
#  - setup/build creates the image and stores it in the unpacker info as
#    'initial_image' and 'current_image'
#  - run runs a container from 'current_image', the commits it into the new
#    'current_image'
#  - upload creates a Dockerfile in a temporary directory, copies all the files
#    to upload there, and builds it. This creates a new 'current_image' with
#    the files replaced
#  - download creates a temporary container from 'current_image' and uses
#    docker cp from it
#  - reset destroys 'current_image' and resets it to 'initial_image'
# This means that a lot of images will get layered on top of each other,
# unfortunately this is necessary so that successive runs carry over the global
# state as expected.


def select_image(runs):
    """Selects a base image for the experiment, with the correct distribution.
    """
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    record_usage(docker_select_box='%s;%s;%s' % (distribution, version,
                                                 architecture))

    if architecture == 'i686':
        logger.info("Wanted architecture was i686, but we'll use x86_64 with "
                    "Docker")
    elif architecture != 'x86_64':
        logger.error("Error: unsupported architecture %s", architecture)
        sys.exit(1)

    def find_distribution(parameter, distribution, version):
        images = parameter['images']
        default = parameter['default']

        for distrib_name, distrib in iteritems(images):
            if distribution == distrib_name:
                result = find_version(distrib, version)
                if result is not None:
                    return result
        distrib = images[default]
        logger.warning("Unsupported distribution '%s', using %s",
                       distribution, default)
        return find_version(distrib, None)

    def find_version(distrib, version):
        if version is not None:
            for image in distrib['versions']:
                if re.match(image['version'], version) is not None:
                    return image['distribution'], image['image']
        image = distrib['default']
        if version is not None:
            logger.warning("Using %s instead of '%s'",
                           image['name'], version)
        return image['distribution'], image['image']

    return find_distribution(get_parameter('docker_images'),
                             distribution, version)


def write_dict(path, dct):
    metadata_write(path, dct, 'docker')


def read_dict(path):
    return metadata_read(path, 'docker')


def docker_setup(args):
    """Does both create and build.

    Removes the directory if building fails.
    """
    docker_setup_create(args)
    try:
        docker_setup_build(args)
    except BaseException:
        Path(args.target[0]).rmtree(ignore_errors=True)
        raise


def docker_setup_create(args):
    """Sets up the experiment to be run in a Docker-built container.
    """
    pack = Path(args.pack[0])
    target = Path(args.target[0])
    if target.exists():
        logger.critical("Target directory exists")
        sys.exit(1)

    signals.pre_setup(target=target, pack=pack)

    target.mkdir()

    try:
        # Unpacks configuration file
        rpz_pack = RPZPack(pack)
        rpz_pack.extract_config(target / 'config.yml')

        # Loads config
        runs, packages, other_files = config = load_config(
            target / 'config.yml', True)

        if args.base_image:
            record_usage(docker_explicit_base=True)
            base_image = args.base_image[0]
            if args.distribution:
                target_distribution = args.distribution[0]
            else:
                target_distribution = None
        else:
            target_distribution, base_image = select_image(runs)
        logger.info("Using base image %s", base_image)
        logger.debug("Distribution: %s", target_distribution or "unknown")

        rpz_pack.copy_data_tar(target / 'data.tgz')

        arch = runs[0]['architecture']

        # Writes Dockerfile
        logger.info("Writing %s...", target / 'Dockerfile')
        with (target / 'Dockerfile').open('w', encoding='utf-8',
                                          newline='\n') as dockerfile:
            dockerfile.write('FROM %s\n\n' % base_image)

            # Installs busybox
            download_file(busybox_url(arch),
                          target / 'busybox',
                          'busybox-%s' % arch)
            dockerfile.write('COPY busybox /busybox\n')

            # Installs rpzsudo
            download_file(sudo_url(arch),
                          target / 'rpzsudo',
                          'rpzsudo-%s' % arch)
            dockerfile.write('COPY rpzsudo /rpzsudo\n\n')

            # Installs rpztar
            download_file(rpztar_url(arch),
                          target / 'rpztar',
                          'rpztar-%s' % arch)
            dockerfile.write('COPY rpztar /rpztar\n\n')

            dockerfile.write('COPY data.tgz /reprozip_data.tgz\n\n')
            dockerfile.write('COPY rpz-files.list /rpz-files.list\n')
            dockerfile.write('RUN \\\n'
                             '    chmod +x /busybox /rpzsudo /rpztar && \\\n')

            if args.install_pkgs:
                # Install every package through package manager
                missing_packages = []
            else:
                # Only install packages that were not packed
                missing_packages = [pkg for pkg in packages if pkg.packfiles]
                packages = [pkg for pkg in packages if not pkg.packfiles]
            if packages:
                record_usage(docker_install_pkgs=True)
                try:
                    installer = select_installer(pack, runs,
                                                 target_distribution)
                except CantFindInstaller as e:
                    logger.error("Need to install %d packages but couldn't "
                                 "select a package installer: %s",
                                 len(packages), e)
                    sys.exit(1)
                # Updates package sources
                update_script = installer.update_script()
                if update_script:
                    dockerfile.write('    %s && \\\n' % update_script)
                # Installs necessary packages
                dockerfile.write(
                    '    %s && \\\n' % installer.install_script(packages),
                )
                logger.info("Dockerfile will install the %d software "
                            "packages that were not packed", len(packages))
            else:
                record_usage(docker_install_pkgs=False)

            # Untar
            paths = set()
            pathlist = []
            # Add intermediate directories, and check for existence in the tar
            logger.info("Generating file list...")
            missing_files = chain.from_iterable(pkg.files
                                                for pkg in missing_packages)
            data_files = rpz_pack.data_filenames()
            listoffiles = list(chain(other_files, missing_files))
            for f in listoffiles:
                if f.path.unicodename in ('resolv.conf', 'hosts') and (
                        f.path.lies_under('/etc') or
                        f.path.lies_under('/run') or
                        f.path.lies_under('/var')):
                    continue
                path = PosixPath('/')
                for c in rpz_pack.remove_data_prefix(f.path).components:
                    path = path / c
                    if path in paths:
                        continue
                    paths.add(path)
                    if path in data_files:
                        if path != '/etc':
                            pathlist.append(path)
                    else:
                        logger.info("Missing file %s", path)
            rpz_pack.close()
            with (target / 'rpz-files.list').open('wb') as filelist:
                for p in pathlist:
                    filelist.write(join_root(PosixPath(''), p).path)
                    filelist.write(b'\0')
            dockerfile.write(
                '    cd / && '
                + '/rpztar /reprozip_data.tgz /rpz-files.list\n',
            )

        # Meta-data for reprounzip
        write_dict(target, metadata_initial_iofiles(config))

        signals.post_setup(target=target, pack=pack)
    except Exception:
        target.rmtree(ignore_errors=True)
        raise


@target_must_exist
def docker_setup_build(args):
    """Builds the container from the Dockerfile
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target)
    if 'initial_image' in unpacked_info:
        logger.critical("Image already built")
        sys.exit(1)

    if args.image_name:
        image = args.image_name[0]
        if not isinstance(image, bytes):
            image = image.encode('ascii')
    else:
        image = make_unique_name(b'reprounzip_image_')

    logger.info("Calling 'docker build'...")
    try:
        retcode = subprocess.call(args.docker_cmd.split() + ['build', '-t'] +
                                  args.docker_option + [image, '.'],
                                  cwd=target.path)
    except OSError:
        logger.critical("docker executable not found")
        sys.exit(1)
    else:
        if retcode != 0:
            logger.critical("docker build failed with code %d", retcode)
            sys.exit(1)
    logger.info("Initial image created: %s", image.decode('ascii'))

    unpacked_info['initial_image'] = image
    unpacked_info['current_image'] = image
    if 'DOCKER_MACHINE_NAME' in os.environ:
        unpacked_info['docker_host'] = {
            'type': 'docker-machine',
            'name': os.environ['DOCKER_MACHINE_NAME']}
    elif 'DOCKER_HOST' in os.environ:
        unpacked_info['docker_host'] = {
            'type': 'custom',
            'env': dict((k, v)
                        for k, v in iteritems(os.environ)
                        if k.startswith('DOCKER_'))}

    write_dict(target, unpacked_info)


@target_must_exist
def docker_reset(args):
    """Reset the image to the initial one.

    This will quickly undo the effects of all the 'upload' and 'run' commands
    on the environment.
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target)
    if 'initial_image' not in unpacked_info:
        logger.critical("Image doesn't exist yet, have you run setup/build?")
        sys.exit(1)
    image = unpacked_info['current_image']
    initial = unpacked_info['initial_image']

    if image == initial:
        logger.warning("Image is already in the initial state, nothing to "
                       "reset")
    else:
        logger.info("Removing image %s", image.decode('ascii'))
        retcode = subprocess.call(args.docker_cmd.split() + ['rmi', image])
        if retcode != 0:
            logger.warning("Can't remove previous image, docker returned %d",
                           retcode)
        unpacked_info['current_image'] = initial
        write_dict(target, unpacked_info)


_addr_re = re.compile(r'^(?:[a-z]+://)?([0-9a-zA-Z_.-]+)(?::[0-9]+)?$')


def get_local_addr():
    """Gets the local IP address of the local machine.

    This finds the address used to connect to the Docker host by establishing a
    network connection to it and reading the local address of the socket.

    Returns an IP address as a unicode object, in digits-and-dots format.

    >>> get_local_addr()
    '172.17.42.1'
    """
    # This function works by creating a socket and connecting to a remote IP.
    # The local address of this socket is assumed to be the address of this
    # machine, that the Docker container can reach.
    target = None

    # Find hostname or IP address in DOCKER_HOST
    if 'DOCKER_HOST' in os.environ:
        m = _addr_re.match(os.environ['DOCKER_HOST'])
        if m is not None:
            target = m.group(1)
            if target.startswith('127.'):
                target = None

    # Else, use whatever local interface lets you connect to google.com
    if target is None:
        target = 'google.com'

    try:
        addresses = socket.getaddrinfo(target, 9, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
    except socket.gaierror:
        pass
    else:
        for address in addresses:
            try:
                af, socktype, proto, canonname, sa = address
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(1)
                sock.connect(sa)
            except socket.error:
                pass
            else:
                addr = sock.getsockname()[0]
                if isinstance(addr, bytes):
                    addr = addr.decode('ascii')
                sock.close()
                return addr

    return '127.0.0.1'


_dockerhost_re = re.compile(r'^tcp://([0-9.]+):[0-9]+$')


@target_must_exist
def docker_run(args):
    """Runs the experiment in the container.
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target)
    cmdline = args.cmdline

    # Sanity check
    if args.detach and args.x11:
        logger.critical("Error: Can't use X11 forwarding if you're detaching")
        raise UsageError

    # Loads config
    config = load_config(target / 'config.yml', True)
    runs = config.runs

    selected_runs = get_runs(runs, args.run, cmdline)

    # Get current image name
    if 'current_image' in unpacked_info:
        image = unpacked_info['current_image']
        logger.debug("Running from image %s", image.decode('ascii'))
    else:
        logger.critical("Image doesn't exist yet, have you run setup/build?")
        sys.exit(1)

    # Name of new container
    if args.detach:
        container = make_unique_name(b'reprounzip_detached_')
    else:
        container = make_unique_name(b'reprounzip_run_')

    hostname = runs[selected_runs[0]].get('hostname', 'reprounzip')

    # Port forwarding
    port_options = []
    for port_host, port_container, proto in parse_ports(args.expose_port):
        port_options.extend(['-p',
                             '%s:%s/%s' % (port_host, port_container, proto)])

    # X11 handler
    if args.x11:
        local_ip = get_local_addr()

        docker_host = local_ip
        if os.environ.get('DOCKER_HOST'):
            m = _dockerhost_re.match(os.environ['DOCKER_HOST'])
            if m is not None:
                docker_host = m.group(1)

        if args.tunneled_x11:
            x11 = X11Handler(True, ('internet', docker_host), args.x11_display)
        else:
            x11 = X11Handler(True, ('internet', local_ip), args.x11_display)

            if (docker_host != local_ip and docker_host != 'localhost' and
                    not docker_host.startswith('127.') and
                    not docker_host.startswith('192.168.99.')):
                ssh_cmdline = ' '.join(
                    '-R*:%(p)d:127.0.0.1:%(p)d' % {'p': port}
                    for port, connector in x11.port_forward)
                logger.warning(
                    "You requested X11 forwarding but the Docker container "
                    "appears to be running remotely. It is probable that it "
                    "won't be able to connect to the local display. Creating "
                    "a remote SSH tunnel and running with --tunneled-x11 "
                    "might help (%s).",
                    ssh_cmdline)
    else:
        x11 = X11Handler(False, ('local', hostname), args.x11_display)

    cmds = []
    for run_number in selected_runs:
        run = runs[run_number]
        cmd = 'cd %s && ' % shell_escape(run['workingdir'])
        cmd += '/busybox env -i '
        environ = x11.fix_env(run['environ'])
        environ = fixup_environment(environ, args)
        cmd += ' '.join('%s=%s' % (shell_escape(k), shell_escape(v))
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
        cmd = '/rpzsudo \'#%d\' \'#%d\' /busybox sh -c %s' % (
            uid, gid,
            shell_escape(cmd))
        cmds.append(cmd)
    cmds = x11.init_cmds + cmds
    cmds = ' && '.join(cmds)

    signals.pre_run(target=target)

    # Creates forwarders
    forwarders = []
    for port, connector in x11.port_forward:
        forwarders.append(LocalForwarder(connector, port))

    if args.detach:
        logger.info("Start container %s (detached)",
                    container.decode('ascii'))
        retcode = interruptible_call(args.docker_cmd.split() +
                                     ['run', b'--name=' + container,
                                      '-h', hostname,
                                      '-d', '-t'] +
                                     port_options +
                                     args.docker_option +
                                     [image, '/busybox', 'sh', '-c', cmds])
        if retcode != 0:
            logger.critical("docker run failed with code %d", retcode)
            subprocess.call(['docker', 'rm', '-f', container])
            sys.exit(1)
        return

    # Run command in container
    logger.info("Starting container %s", container.decode('ascii'))
    retcode = interruptible_call(args.docker_cmd.split() +
                                 ['run', b'--name=' + container,
                                  '-h', hostname,
                                  '-i', '-t'] +
                                 port_options +
                                 args.docker_option +
                                 [image, '/busybox', 'sh', '-c', cmds],
                                 request_tty=True)

    # Get exit status from "docker inspect"
    try:
        out = subprocess.check_output(args.docker_cmd.split() +
                                      ['inspect', container])
    except subprocess.CalledProcessError:
        logger.critical("docker run failed with code %d", retcode)
        subprocess.call(['docker', 'rm', '-f', container])
        sys.exit(1)
    outjson = json.loads(out.decode('utf-8'))
    if (outjson[0]["State"]["Running"] is not False or
            outjson[0]["State"]["Paused"] is not False):
        logger.error("Invalid container state after execution:\n%s",
                     json.dumps(outjson[0]["State"]))
    retcode = outjson[0]["State"]["ExitCode"]
    stderr.write("\n*** Command finished, status: %d\n" % retcode)

    # Commit to create new image
    new_image = make_unique_name(b'reprounzip_image_')
    logger.info("Committing container %s to image %s",
                container.decode('ascii'), new_image.decode('ascii'))
    subprocess.check_call(args.docker_cmd.split() +
                          ['commit', container, new_image])

    # Update image name
    unpacked_info['current_image'] = new_image
    write_dict(target, unpacked_info)

    # Remove the container
    logger.info("Destroying container %s", container.decode('ascii'))
    retcode = subprocess.call(args.docker_cmd.split() + ['rm', container])
    if retcode != 0:
        logger.error("Error deleting container %s", container.decode('ascii'))

    # Untag previous image, unless it is the initial_image
    if image != unpacked_info['initial_image']:
        logger.info("Untagging previous image %s", image.decode('ascii'))
        subprocess.check_call(args.docker_cmd.split() + ['rmi', image])

    # Update input file status
    metadata_update_run(config, unpacked_info, selected_runs)
    write_dict(target, unpacked_info)

    signals.post_run(target=target, retcode=retcode)


class ContainerUploader(FileUploader):
    def __init__(self, target, input_files, files, unpacked_info,
                 docker_cmd=['docker']):
        self.unpacked_info = unpacked_info
        self.docker_cmd = docker_cmd
        config = load_config(target / 'config.yml', True)
        if config.runs:
            first_run = config.runs[0]
            self.default_ownership = (
                first_run.get('uid'),
                first_run.get('gid'),
            )
        else:
            self.default_ownership = None, None

        FileUploader.__init__(self, target, input_files, files)

    def prepare_upload(self, files):
        if 'current_image' not in self.unpacked_info:
            stderr.write("Image doesn't exist yet, have you run "
                         "setup/build?\n")
            sys.exit(1)

        self.build_directory = Path.tempdir(prefix='reprozip_build_')
        self.docker_copy = []

    def upload_file(self, local_path, input_path):
        stem, ext = local_path.stem, local_path.ext
        name = local_path.name
        nb = 0
        while (self.build_directory / name).exists():
            nb += 1
            name = stem + ('_%d' % nb).encode('ascii') + ext
        name = Path(name)
        local_path.copyfile(self.build_directory / name)
        logger.info("Copied file %s to %s", local_path, name)
        self.docker_copy.append((name, input_path))

    def finalize(self):
        if not self.docker_copy:
            self.build_directory.rmtree()
            return

        from_image = self.unpacked_info['current_image']

        with self.build_directory.open('w', 'Dockerfile',
                                       encoding='utf-8',
                                       newline='\n') as dockerfile:
            dockerfile.write('FROM %s\n\n' % from_image.decode('ascii'))
            for src, target in self.docker_copy:
                # FIXME : spaces in filenames will probably break Docker
                dockerfile.write(
                    'COPY \\\n    %s \\\n    %s\n' % (
                        shell_escape(unicode_(src)),
                        shell_escape(unicode_(target))))

            for src, target in self.docker_copy:
                uid = gid = None

                # Keep permissions if the file is already in there
                tar = tarfile.open(str(self.target / 'data.tgz'), 'r:*')
                try:
                    info = tar.getmember(str(
                        join_root(PosixPath(b'DATA'), target)
                    ))
                    uid, gid = info.uid, info.gid
                except KeyError:
                    pass

                # Otherwise default on the first run's UID/GID
                if uid is None:
                    uid, gid = self.default_ownership

                # Lastly, use 1000
                if uid is None:
                    uid = gid = 1000

                dockerfile.write(
                    'RUN ["/busybox", "chown", "%d:%d", %s]\n' % (
                        uid, gid, json.dumps(unicode_(target)),
                    )
                )

        image = make_unique_name(b'reprounzip_image_')
        retcode = subprocess.call(self.docker_cmd +
                                  ['build', '-t', image, '.'],
                                  cwd=self.build_directory.path)
        if retcode != 0:
            logger.critical("docker build failed with code %d", retcode)
            sys.exit(1)
        else:
            logger.info("New image created: %s", image.decode('ascii'))
            if from_image != self.unpacked_info['initial_image']:
                logger.info("Untagging previous image %s",
                            from_image.decode('ascii'))
                retcode = subprocess.call(self.docker_cmd +
                                          ['rmi', from_image])
                if retcode != 0:
                    logger.warning("Can't remove previous image, docker "
                                   "returned %d", retcode)
            self.unpacked_info['current_image'] = image
            write_dict(self.target, self.unpacked_info)

        self.build_directory.rmtree()


@target_must_exist
def docker_upload(args):
    """Replaces an input file in the container.
    """
    target = Path(args.target[0])
    files = args.file
    unpacked_info = read_dict(target)
    input_files = unpacked_info.setdefault('input_files', {})

    try:
        ContainerUploader(target, input_files, files, unpacked_info,
                          docker_cmd=args.docker_cmd.split())
    finally:
        write_dict(target, unpacked_info)


class ContainerDownloader(FileDownloader):
    def __init__(self, target, files, image, all_=False,
                 docker_cmd=['docker']):
        self.image = image
        self.docker_cmd = docker_cmd
        FileDownloader.__init__(self, target, files, all_=all_)

    def prepare_download(self, files):
        # Create a container from the image
        self.container = make_unique_name(b'reprounzip_dl_')
        logger.info("Creating container %s", self.container.decode('ascii'))
        subprocess.check_call(self.docker_cmd +
                              ['create',
                               b'--name=' + self.container,
                               self.image])

    def download(self, remote_path, local_path):
        # Docker copies to a file in the specified directory, cannot just take
        # a file name (#4272)
        tmpdir = Path.tempdir(prefix='reprozip_docker_output_')
        try:
            ret = subprocess.call(self.docker_cmd +
                                  ['cp',
                                   self.container + b':' + remote_path.path,
                                   tmpdir.path])
            if ret != 0:
                logger.critical("Can't get output file: %s", remote_path)
                return False
            (tmpdir / remote_path.name).copyfile(local_path)
        finally:
            tmpdir.rmtree()
        return True

    def finalize(self):
        logger.info("Removing container %s", self.container.decode('ascii'))
        retcode = subprocess.call(self.docker_cmd + ['rm', self.container])
        if retcode != 0:
            logger.warning("Can't remove temporary container, docker "
                           "returned %d", retcode)


@target_must_exist
def docker_download(args):
    """Gets an output file out of the container.
    """
    target = Path(args.target[0])
    files = args.file
    unpacked_info = read_dict(target)

    if 'current_image' not in unpacked_info:
        logger.critical("Image doesn't exist yet, have you run setup/build?")
        sys.exit(1)
    image = unpacked_info['current_image']
    logger.debug("Downloading from image %s", image.decode('ascii'))

    ContainerDownloader(target, files, image,
                        all_=args.all, docker_cmd=args.docker_cmd.split())


@target_must_exist
def docker_destroy_docker(args):
    """Destroys the container and images.
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target)
    if 'initial_image' not in unpacked_info:
        logger.critical("Image not created")
        sys.exit(1)

    initial_image = unpacked_info.pop('initial_image')

    if 'current_image' in unpacked_info:
        image = unpacked_info.pop('current_image')
        if image != initial_image:
            logger.info("Destroying image %s...", image.decode('ascii'))
            retcode = subprocess.call(args.docker_cmd.split() + ['rmi', image])
            if retcode != 0:
                logger.error("Error deleting image %s", image.decode('ascii'))

    logger.info("Destroying image %s...", initial_image.decode('ascii'))
    retcode = subprocess.call(args.docker_cmd.split() + ['rmi', initial_image])
    if retcode != 0:
        logger.error("Error deleting image %s", initial_image.decode('ascii'))


@target_must_exist
def docker_destroy_dir(args):
    """Destroys the directory.
    """
    target = Path(args.target[0])
    read_dict(target)

    logger.info("Removing directory %s...", target)
    signals.pre_destroy(target=target)
    target.rmtree()
    signals.post_destroy(target=target)


def test_has_docker(pack, **kwargs):
    """Compatibility test: has docker (ok) or not (maybe).
    """
    pathlist = os.environ['PATH'].split(os.pathsep) + ['.']
    pathexts = os.environ.get('PATHEXT', '').split(os.pathsep)
    for path in pathlist:
        for ext in pathexts:
            fullpath = os.path.join(path, 'docker') + ext
            if os.path.isfile(fullpath):
                return COMPAT_OK
    return COMPAT_MAYBE, "docker not found in PATH"


def setup(parser, **kwargs):
    """Runs the experiment in a Docker container

    You will need Docker to be installed on your machine if you want to run the
    experiment.

    setup   setup/create    creates Dockerfile (needs the pack filename)
            setup/build     builds the container from the Dockerfile
    reset                   resets the Docker image to the initial state (just
                            after setup)
    upload                  replaces input files in the container
                            (without arguments, lists input files)
    run                     runs the experiment in the container
    download                gets output files from the container
                            (without arguments, lists output files)
    destroy destroy/docker  destroys the container and associated images
            destroy/dir     removes the unpacked directory

    For example:

        $ reprounzip docker setup mypack.rpz experiment; cd experiment
        $ reprounzip docker run .
        $ reprounzip docker download . results:/home/user/theresults.txt
        $ cd ..; reprounzip docker destroy experiment

    Upload specifications are either:
      :input_id             restores the original input file from the pack
      filename:input_id     replaces the input file with the specified local
                            file

    Download specifications are either:
      output_id:            print the output file to stdout
      output_id:filename    extracts the output file to the corresponding local
                            path
    """
    parser.add_argument('--docker-cmd', action='store', default='docker',
                        help="Change the Docker command; split on spaces")

    subparsers = parser.add_subparsers(title="actions",
                                       metavar='', help=argparse.SUPPRESS)

    def add_opt_general(opts):
        opts.add_argument('target', nargs=1, help="Experiment directory")

    # Common between setup and setup/create
    def add_opt_setup_create(opts):
        opts.add_argument('pack', nargs=1, help="Pack to extract")
        opts.add_argument('--base-image', nargs=1, help="Base image to use")
        opts.add_argument('--distribution', nargs=1,
                          help="Distribution used in the base image (for "
                               "package installer selection)")
        opts.add_argument('--install-pkgs', action='store_true',
                          default=False,
                          help="Install packages rather than extracting "
                               "them from RPZ file")
        opts.add_argument('--unpack-pkgs', action='store_false',
                          default=False, dest='install_pkgs',
                          help=argparse.SUPPRESS)

    # Common between setup and setup/build
    def add_opt_setup_build(opts):
        opts.add_argument('--image-name', nargs=1,
                          help="Name of the image to create (by default, a "
                               "random name beginning with "
                               "'reprounzip_image_' is generated)")
        add_raw_docker_option(opts)

    # --docker-option
    def add_raw_docker_option(opts):
        opts.add_argument('--docker-option', action='append',
                          default=[],
                          help="Argument passed to Docker directly; may be "
                               "specified multiple times")

    parser_setup_create = subparsers.add_parser('setup/create')
    add_opt_setup_create(parser_setup_create)
    add_opt_general(parser_setup_create)
    parser_setup_create.set_defaults(func=docker_setup_create)

    # setup/build
    parser_setup_build = subparsers.add_parser('setup/build')
    add_opt_general(parser_setup_build)
    add_opt_setup_build(parser_setup_build)
    parser_setup_build.set_defaults(func=docker_setup_build)

    # setup
    parser_setup = subparsers.add_parser('setup')
    add_opt_setup_create(parser_setup)
    add_opt_setup_build(parser_setup)
    add_opt_general(parser_setup)
    parser_setup.set_defaults(func=docker_setup)

    # reset
    parser_reset = subparsers.add_parser('reset')
    add_opt_general(parser_reset)
    parser_reset.set_defaults(func=docker_reset)

    # upload
    parser_upload = subparsers.add_parser('upload')
    add_opt_general(parser_upload)
    parser_upload.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                               help="<path>:<input_file_name>")
    parser_upload.set_defaults(func=docker_upload)

    # run
    parser_run = subparsers.add_parser('run')
    add_opt_general(parser_run)
    parser_run.add_argument('run', default=None, nargs=argparse.OPTIONAL)
    parser_run.add_argument('--cmdline', nargs=argparse.REMAINDER,
                            help="Command line to run")
    parser_run.add_argument('--expose-port', '-p', action='append', default=[],
                            help="Expose a network port, "
                                 "host[:experiment[/proto]]. Example: 8000:80")
    parser_run.add_argument('--enable-x11', action='store_true', default=False,
                            dest='x11',
                            help="Enable X11 support (needs an X server on "
                                 "the host)")
    parser_run.add_argument('--x11-display', dest='x11_display',
                            help="Display number to use on the experiment "
                                 "side (change the host display with the "
                                 "DISPLAY environment variable)")
    parser_run.add_argument(
        '--tunneled-x11', dest='tunneled_x11',
        action='store_true', default=False,
        help="Connect X11 to local machine from Docker container instead of "
             "trying to connect to this one (useful if the Docker machine has "
             "an X server or if a tunnel is used to access this one)")
    parser_run.add_argument('-d', '--detach', action='store_true',
                            help="Don't attach or commit the created "
                                 "container, just start it and leave it be")
    add_raw_docker_option(parser_run)
    add_environment_options(parser_run)
    parser_run.set_defaults(func=docker_run)

    # download
    parser_download = subparsers.add_parser('download')
    add_opt_general(parser_download)
    parser_download.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                                 help="<output_file_name>[:<path>]")
    parser_download.add_argument('--all', action='store_true',
                                 help="Download all output files to the "
                                      "current directory")
    parser_download.set_defaults(func=docker_download)

    # destroy/docker
    parser_destroy_docker = subparsers.add_parser('destroy/docker')
    add_opt_general(parser_destroy_docker)
    parser_destroy_docker.set_defaults(func=docker_destroy_docker)

    # destroy/dir
    parser_destroy_dir = subparsers.add_parser('destroy/dir')
    add_opt_general(parser_destroy_dir)
    parser_destroy_dir.set_defaults(func=docker_destroy_dir)

    # destroy
    parser_destroy = subparsers.add_parser('destroy')
    add_opt_general(parser_destroy)
    parser_destroy.set_defaults(func=composite_action(docker_destroy_docker,
                                                      docker_destroy_dir))

    return {'test_compatibility': test_has_docker}
