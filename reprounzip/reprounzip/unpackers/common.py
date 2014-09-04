# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions for unpacker plugins.

This contains functions related to shell scripts, package managers, and the
pack files.
"""

from __future__ import unicode_literals

import functools
import logging
import os
import platform
import random
from rpaths import PosixPath, Path
import string
import subprocess
import sys
import tarfile

import reprounzip.common
from reprounzip.utils import irange, itervalues


THIS_DISTRIBUTION = platform.linux_distribution()[0].lower()


PKG_NOT_INSTALLED = "(not installed)"


COMPAT_OK = 0
COMPAT_NO = 1
COMPAT_MAYBE = 2


def composite_action(*functions):
    def wrapper(args):
        for function in functions:
            function(args)
    return wrapper


def target_must_exist(func):
    @functools.wraps(func)
    def wrapper(args):
        target = Path(args.target[0])
        if not target.is_dir():
            logging.critical("Error: Target directory doesn't exist")
            sys.exit(1)
        return func(args)
    return wrapper


def unique_names():
    """Generates unique sequences of bytes.
    """
    characters = (b"abcdefghijklmnopqrstuvwxyz"
                  b"0123456789")
    characters = [characters[i:i + 1] for i in irange(len(characters))]
    rng = random.Random()
    while True:
        letters = [rng.choice(characters) for i in irange(10)]
        yield b''.join(letters)
unique_names = unique_names()


def make_unique_name(prefix):
    assert isinstance(prefix, bytes)
    return prefix + next(unique_names)


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
            logging.critical("Unknown pack format")
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
        for pkg, status in itervalues(pkgs_status):
            if status is not None:
                required_pkgs.discard(pkg.name)
        if required_pkgs:
            logging.error("Error: some packages could not be installed:%s" %
                          ''.join("\n    %s" % pkg for pkg in required_pkgs))

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
        logging.warning("Installing on %s but pack was generated on %s" % (
                        target_distribution.capitalize(),
                        orig_distribution.capitalize()))
    elif orig_distribution != target_distribution:
        logging.error("Installing on %s but pack was generated on %s" % (
                      target_distribution.capitalize(),
                      orig_distribution.capitalize()))
        sys.exit(1)

    # Selects installation method
    if target_distribution == 'ubuntu':
        installer = AptInstaller('apt-get')
    elif target_distribution == 'debian':
        # aptitude is not installed by default, so use apt-get here too
        installer = AptInstaller('apt-get')
    else:
        logging.critical("Your current distribution, \"%s\", is not "
                         "supported" %
                         (target_distribution or "(unknown)").capitalize())
        sys.exit(1)

    return installer


def busybox_url(arch):
    return 'http://www.busybox.net/downloads/binaries/latest/busybox-%s' % arch


def join_root(root, path):
    p_root, p_loc = path.split_root()
    assert p_root == b'/'
    return root / p_loc


class FileUploader(object):
    """Common logic for 'upload' commands.
    """
    def __init__(self, target, input_files, files):
        self.target = target
        self.input_files = input_files
        self.run(files)

    def run(self, files):
        runs = self.get_runs_from_config()

        # No argument: list all the input files and exit
        if not files:
            print("Input files:")
            for i, run in enumerate(runs):
                if len(runs) > 1:
                    print("  Run %d:" % i)
                for input_name in run['input_files']:
                    assigned = self.input_files.get(input_name) or "(original)"
                    print("    %s: %s" % (input_name, assigned))
            return

        self.prepare_upload(files)

        # Get the path of each input file
        all_input_files = {}
        for run in runs:
            all_input_files.update(run['input_files'])

        try:
            # Upload files
            for filespec in files:
                filespec_split = filespec.rsplit(':', 1)
                if len(filespec_split) != 2:
                    logging.critical("Invalid file specification: %r" %
                                     filespec)
                    sys.exit(1)
                local_path, input_name = filespec_split

                try:
                    input_path = PosixPath(all_input_files[input_name])
                except KeyError:
                    logging.critical("Invalid input name: %r" % input_name)
                    sys.exit(1)

                temp = None

                if not local_path:
                    # Restore original file from pack
                    fd, temp = Path.tempfile(prefix='reprozip_input_')
                    os.close(fd)
                    tar = tarfile.open(str(self.target / 'experiment.rpz'),
                                       'r:*')
                    member = tar.getmember(str(join_root(PosixPath('DATA'),
                                                         input_path)))
                    member.name = str(temp.name)
                    tar.extract(member, str(temp.parent))
                    tar.close()
                    local_path = temp
                else:
                    local_path = Path(local_path)
                    if not local_path.exists():
                        logging.critical("Local file %s doesn't exist" %
                                         local_path)
                        sys.exit(1)

                self.upload_file(local_path, input_path)

                if temp is not None:
                    temp.remove()
                    self.input_files[input_name] = None
                else:
                    self.input_files[input_name] = local_path.absolute().path
        finally:
            self.finalize()

    def get_runs_from_config(self):
        # Loads config
        runs, packages, other_files = load_config(
                self.target / 'experiment.rpz')
        return runs

    def prepare_upload(self, files):
        pass

    def upload_file(self, local_path, input_path):
        raise NotImplementedError

    def finalize(self):
        pass


class FileDownloader(object):
    def __init__(self, target, files):
        self.target = target
        self.run(files)

    def run(self, files):
        runs = self.get_runs_from_config()

        # No argument: list all the output files and exit
        if not files:
            print("Output files:")
            for i, run in enumerate(runs):
                if len(runs) > 1:
                    print("  Run %d:" % i)
                for output_name in run['output_files']:
                    print("    %s" % output_name)
            return

        self.prepare_download(files)

        # Get the path of each output file
        all_output_files = {}
        for run in runs:
            all_output_files.update(run['output_files'])

        try:
            # Download files
            for filespec in files:
                filespec_split = filespec.split(':', 1)
                if len(filespec_split) != 2:
                    logging.critical("Invalid file specification: %r" %
                                     filespec)
                    sys.exit(1)
                output_name, local_path = filespec_split

                try:
                    remote_path = PosixPath(all_output_files[output_name])
                except KeyError:
                    logging.critical("Invalid output name: %r" % output_name)
                    sys.exit(1)

                if not local_path:
                    self.download_and_print(remote_path)
                else:
                    self.download(remote_path, Path(local_path))
        finally:
            self.finalize()

    def get_runs_from_config(self):
        # Loads config
        runs, packages, other_files = load_config(
                self.target / 'experiment.rpz')
        return runs

    def prepare_download(self, files):
        pass

    def download_and_print(self, remote_path):
        # Download to temporary file
        fd, temp = Path.tempfile(prefix='reprozip_output_')
        os.close(fd)
        self.download(remote_path, temp)
        # Output to stdout
        with temp.open('rb') as fp:
            chunk = fp.read(1024)
            if chunk:
                sys.stdout.write(chunk)
            while len(chunk) == 1024:
                chunk = fp.read(1024)
                if chunk:
                    sys.stdout.write(chunk)
        temp.remove()

    def download(self, remote_path, local_path):
        raise NotImplementedError

    def finalize(self):
        pass


def get_runs(runs, selected_run, cmdline):
    if selected_run is None and len(runs) == 1:
        selected_run = 0

    # --cmdline without arguments: display the original command line
    if cmdline == []:
        if selected_run is None:
            logging.critical("There are several runs in this pack -- you have "
                             "to choose which one to use with --cmdline")
            sys.exit(1)
        print("Original command-line:")
        print(' '.join(shell_escape(arg)
                       for arg in runs[selected_run]['argv']))
        sys.exit(0)

    if selected_run is None:
        selected_run = irange(len(runs))
    else:
        selected_run = (int(selected_run),)

    return selected_run
