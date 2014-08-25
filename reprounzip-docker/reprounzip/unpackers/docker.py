"""Docker plugin for reprounzip.

This files contains the 'docker' unpacker, which builds a Dockerfile from a
reprozip pack. You can then build a container and run it with Docker.

See http://www.docker.io/
"""

# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import argparse
import logging
import os
import pickle
import random
from rpaths import Path, PosixPath
import subprocess
import sys
import tarfile

from reprounzip.unpackers.common import load_config, select_installer, \
    composite_action, target_must_exist, COMPAT_OK, COMPAT_MAYBE, join_root, \
    shell_escape
from reprounzip.utils import unicode_


def docker_escape(s):
    return '"%s"' % (s.replace('\\', '\\\\')
                      .replace('"', '\\"'))


def select_image(runs):
    distribution, version = runs[0]['distribution']
    distribution = distribution.lower()
    architecture = runs[0]['architecture']

    if architecture == 'i686':
        sys.stderr.write("Warning: wanted architecture was i686, but we'll "
                         "use x86_64 with Docker")
    elif architecture != 'x86_64':
        sys.stderr.write("Error: unsupported architecture %s\n" % architecture)
        sys.exit(1)

    # Ubuntu
    if distribution == 'ubuntu':
        if version != '12.04':
            sys.stderr.write("Warning: using Ubuntu 12.04 'Precise' instead "
                             "of '%s'\n" % version)
        return 'ubuntu', 'ubuntu:12.04'

    # Debian
    elif distribution != 'debian':
        sys.stderr.write("Warning: unsupported distribution %s, using Debian"
                         "\n" % distribution)
        distribution = 'debian', '7'

    if version == '6' or version.startswith('squeeze'):
        return 'debian', 'debian:squeeze'
    if version == '8' or version.startswith('jessie'):
        return 'debian', 'debian:jessie'
    else:
        if version != '7' and not version.startswith('wheezy'):
            sys.stderr.write("Warning: using Debian 7 'Wheezy' instead of '%s'"
                             "\n" % version)
        return 'debian', 'debian:wheezy'


def write_dict(filename, dct):
    to_write = {'unpacker': 'docker'}
    to_write.update(dct)
    with filename.open('wb') as fp:
        pickle.dump(to_write, fp, pickle.HIGHEST_PROTOCOL)


def read_dict(filename):
    with filename.open('rb') as fp:
        dct = pickle.load(fp)
    assert dct['unpacker'] == 'docker'
    return dct


def image_tags():
    """Generates unique image names.
    """
    characters = (b"abcdefghijklmnopqrstuvwxyz"
                  b"0123456789")
    rng = random.Random()
    while True:
        letters = [rng.choice(characters) for i in xrange(10)]
        yield b'reprounzip_' + ''.join(letters)
image_tags = image_tags()


def docker_setup_create(args):
    """Sets up the experiment to be run in a Docker-built container.
    """
    pack = Path(args.pack[0])
    target = Path(args.target[0])
    if target.exists():
        sys.stderr.write("Error: Target directory exists\n")
        sys.exit(1)

    # Loads config
    runs, packages, other_files = load_config(pack)

    if args.base_image:
        target_distribution = None
        base_image = args.base_image[0]
    else:
        target_distribution, base_image = select_image(runs)

    target.mkdir(parents=True)
    pack.copyfile(target / 'experiment.rpz')

    # Writes Dockerfile
    with (target / 'Dockerfile').open('w',
                                      encoding='utf-8', newline='\n') as fp:
        fp.write('FROM %s\n\n' % base_image)
        fp.write('COPY experiment.rpz /reprozip_experiment.rpz\n\n')
        fp.write('RUN \\\n')

        # Installs missing packages
        packages = [pkg for pkg in packages if not pkg.packfiles]
        if packages:
            installer = select_installer(pack, runs, target_distribution)
            # Updates package sources
            fp.write('    %s && \\\n' % installer.update_script())
            # Installs necessary packages
            fp.write('    %s && \\\n' % installer.install_script(packages))

        # Untar
        paths = set()
        pathlist = []
        dataroot = PosixPath('DATA')
        # Adds intermediate directories, and checks for existence in the tar
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
                    logging.info("Missing file %s" % datapath)
                else:
                    pathlist.append(unicode_(datapath))
        tar.close()
        # FIXME : for some reason we need reversed() here, I'm not sure why.
        # Need to read more of tar's docs.
        # TAR bug: --no-overwrite-dir removes --keep-old-files
        fp.write('    cd / && tar zpxf /reprozip_experiment.rpz '
                 '--numeric-owner --strip=1 %s\n' %
                 ' '.join(shell_escape(p) for p in reversed(pathlist)))

    # Meta-data for reprounzip
    write_dict(target / '.reprounzip', {})


@target_must_exist
def docker_setup_build(args):
    """Builds the container from the Dockerfile
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target / '.reprounzip')
    if 'initial_image' in unpacked_info:
        sys.stderr.write("Image already built\n")
        sys.exit(1)

    tag = next(image_tags)

    retcode = subprocess.call(['docker', 'build', '-t', tag, '.'],
                              cwd=target.path)
    if retcode != 0:
        sys.stderr.write("docker build failed with code %d\n" % retcode)
        sys.exit(1)

    unpacked_info['initial_image'] = tag
    unpacked_info['current_image'] = tag


@target_must_exist
def docker_destroy_docker(args):
    """Destroys the container and images.
    """
    target = Path(args.target[0])
    unpacked_info = read_dict(target / '.reprounzip')
    if 'initial_image' not in unpacked_info:
        sys.stderr.write("Image not created\n")
        sys.exit(1)

    # TODO : destroys images and containers


@target_must_exist
def docker_destroy_dir(args):
    """Destroys the directory.
    """
    target = Path(args.target[0])
    read_dict(target / '.reprounzip')

    target.rmtree()


def test_has_docker(pack, **kwargs):
    pathlist = os.environ['PATH'].split(os.pathsep) + ['.']
    pathexts = os.environ.get('PATHEXT', '').split(os.pathsep)
    for path in pathlist:
        for ext in pathexts:
            fullpath = os.path.join(path, 'docker') + ext
            if os.path.isfile(fullpath):
                return COMPAT_OK
    return COMPAT_MAYBE, "docker not found in PATH"


def setup(parser):
    """Runs the experiment in a Docker container

    You will need Docker to be installed on your machine if you want to run the
    experiment.

    setup   setup/create    creates Dockerfile (--pack is required)
            setup/build     builds the container from the Dockerfile
    upload                  replaces input files in the container
                            (without arguments, lists input files)
    run                     runs the experiment in the container
    download                gets output files from the container
                            (without arguments, lists output files)
    destroy destroy/docker  destroys the container and associated images
            destroy/dir     removes the unpacked directory

    For example:

        $ reprounzip docker setup --pack mypack.rpz experiment; cd experiment
        $ reprounzip docker run .
        $ reprounzip docker download . results:/home/user/theresults.txt
        $ cd ..; reprounzip docker destroy experiment
    """
    subparsers = parser.add_subparsers(title="actions",
                                       metavar='', help=argparse.SUPPRESS)
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('target', nargs=1, help="Directory to create")

    # setup/create
    opt_setup = argparse.ArgumentParser(add_help=False)
    opt_setup.add_argument('--pack', nargs=1, help="Pack to extract")
    opt_setup.add_argument('--base-image', nargs=1, help="Base image to use")
    parser_setup_create = subparsers.add_parser('/setup/create',
                                                parents=[options, opt_setup])
    parser_setup_create.set_defaults(func=docker_setup_create)

    # setup/build
    parser_setup_build = subparsers.add_parser('setup/build',
                                               parents=[options])
    parser_setup_build.set_defaults(func=docker_setup_build)

    # setup
    parser_setup = subparsers.add_parser('setup', parents=[options, opt_setup])
    parser_setup.set_defaults(func=composite_action(docker_setup_create,
                                                    docker_setup_build))

    # TODO : docker upload

    # TODO : docker run

    # TODO : docker download

    # destroy/docker
    parser_destroy_docker = subparsers.add_parser('destroy/docker',
                                                  parents=[options])
    parser_destroy_docker.set_defaults(func=docker_destroy_docker)

    # destroy/dir
    parser_destroy_dir = subparsers.add_parser('destroy/dir',
                                               parents=[options])
    parser_destroy_dir.set_defaults(func=docker_destroy_dir)

    # destroy
    parser_destroy = subparsers.add_parser('destroy', parents=[options])
    parser_destroy.set_defaults(func=composite_action(docker_destroy_docker,
                                                      docker_destroy_dir))

    return {'test_compatibility': test_has_docker}
