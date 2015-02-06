# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Miscellaneous utilities for unpacker plugins.
"""

from __future__ import unicode_literals

import functools
import logging
import os
import random
from rpaths import PosixPath, Path
import signal
import string
import subprocess
import sys
import tarfile

import reprounzip.common
from reprounzip.utils import irange


COMPAT_OK = 0
COMPAT_NO = 1
COMPAT_MAYBE = 2


class UsageError(Exception):
    def __init__(self, msg="Invalid command-line"):
        Exception.__init__(self, msg)


def composite_action(*functions):
    """Makes an action that just calls several other actions in sequence.

    Useful to implement ``myplugin setup`` in terms of ``myplugin setup/part1``
    and ``myplugin setup/part2``: simply use
    ``act1n2 = composite_action(act1, act2)``.
    """
    def wrapper(args):
        for function in functions:
            function(args)
    return wrapper


def target_must_exist(func):
    """Decorator that checks that ``args.target`` exists.
    """
    @functools.wraps(func)
    def wrapper(args):
        target = Path(args.target[0])
        if not target.is_dir():
            logging.critical("Error: Target directory doesn't exist")
            raise UsageError
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
    """Makes a unique (random) bytestring name, starting with the given prefix.
    """
    assert isinstance(prefix, bytes)
    return prefix + next(unique_names)


def shell_escape(s):
    """Given bl"a, returns "bl\\"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if any(c in s for c in string.whitespace + '*$\\"\''):
        return '"%s"' % (s.replace('\\', '\\\\')
                          .replace('"', '\\"')
                          .replace('$', '\\$'))
    else:
        return s


def load_config(pack):
    """Utility method loading the YAML configuration from inside a pack file.

    Decompresses the config.yml file from the tarball to a temporary file then
    loads it. Note that decompressing a single file is inefficient, thus
    calling this method can be slow.
    """
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


def busybox_url(arch):
    """Gets the correct URL for the busybox binary given the architecture.
    """
    return 'http://www.busybox.net/downloads/binaries/latest/busybox-%s' % arch


def join_root(root, path):
    """Prepends `root` to the absolute path `path`.
    """
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
        reprounzip.common.record_usage(upload_files=len(files))
        runs = self.get_runs_from_config()

        # No argument: list all the input files and exit
        if not files:
            print("Input files:")
            for i, run in enumerate(runs):
                if len(runs) > 1:
                    print("  Run %d:" % i)
                for input_name in run['input_files']:
                    if self.input_files.get(input_name) is not None:
                        assigned = PosixPath(self.input_files[input_name])
                    else:
                        assigned = "(original)"
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
                    logging.critical("Invalid file specification: %r",
                                     filespec)
                    sys.exit(1)
                local_path, input_name = filespec_split

                try:
                    input_path = PosixPath(all_input_files[input_name])
                except KeyError:
                    logging.critical("Invalid input file: %r", input_name)
                    sys.exit(1)

                temp = None

                if not local_path:
                    # Restore original file from pack
                    logging.debug("Restoring input file %s", input_path)
                    fd, temp = Path.tempfile(prefix='reprozip_input_')
                    os.close(fd)
                    local_path = self.extract_original_input(input_name,
                                                             input_path,
                                                             temp)
                else:
                    local_path = Path(local_path)
                    logging.debug("Uploading file %s to %s",
                                  local_path, input_path)
                    if not local_path.exists():
                        logging.critical("Local file %s doesn't exist",
                                         local_path)
                        sys.exit(1)

                self.upload_file(local_path, input_path)

                if temp is not None:
                    temp.remove()
                    self.input_files.pop(input_name, None)
                else:
                    self.input_files[input_name] = local_path.absolute().path
        finally:
            self.finalize()

    def get_runs_from_config(self):
        # Loads config
        runs, packages, other_files = reprounzip.common.load_config(
                self.target / 'config.yml',
                canonical=True)
        return runs

    def prepare_upload(self, files):
        pass

    def extract_original_input(self, input_name, input_path, temp):
        tar = tarfile.open(str(self.target / 'experiment.rpz'), 'r:*')
        member = tar.getmember(str(join_root(PosixPath('DATA'), input_path)))
        member.name = str(temp.name)
        tar.extract(member, str(temp.parent))
        tar.close()
        return temp

    def upload_file(self, local_path, input_path):
        raise NotImplementedError

    def finalize(self):
        pass


class FileDownloader(object):
    """Common logic for 'download' commands.
    """
    def __init__(self, target, files):
        self.target = target
        self.run(files)

    def run(self, files):
        reprounzip.common.record_usage(download_files=len(files))
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
                    logging.critical("Invalid file specification: %r",
                                     filespec)
                    sys.exit(1)
                output_name, local_path = filespec_split

                try:
                    remote_path = PosixPath(all_output_files[output_name])
                except KeyError:
                    logging.critical("Invalid output file: %r", output_name)
                    sys.exit(1)

                logging.debug("Downloading file %s", remote_path)
                if not local_path:
                    self.download_and_print(remote_path)
                else:
                    self.download(remote_path, Path(local_path))
        finally:
            self.finalize()

    def get_runs_from_config(self):
        # Loads config
        runs, packages, other_files = reprounzip.common.load_config(
                self.target / 'config.yml',
                canonical=True)
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
                sys.stdout.buffer.write(chunk)
            while len(chunk) == 1024:
                chunk = fp.read(1024)
                if chunk:
                    sys.stdout.buffer.write(chunk)
        temp.remove()

    def download(self, remote_path, local_path):
        raise NotImplementedError

    def finalize(self):
        pass


def get_runs(runs, selected_run, cmdline):
    """Selects which run(s) to execute based on parts of the command-line.

    Will return an iterable of run numbers. Might also fail loudly or exit
    after printing the original command-line.
    """
    if selected_run is None and len(runs) == 1:
        selected_run = 0
    elif selected_run is not None:
        try:
            selected_run = int(selected_run)
        except ValueError:
            logging.critical("Error: Run is not a number")
            raise UsageError
        if selected_run < 0 or selected_run >= len(runs):
            logging.critical("Error: Expected 0 <= run <= %d, got %d",
                             len(runs) - 1, selected_run)
            sys.exit(1)

    # --cmdline without arguments: display the original command-line
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


def interruptible_call(*args, **kwargs):
    assert signal.getsignal(signal.SIGINT) == signal.default_int_handler
    proc = [None]

    def _sigint_handler(signum, frame):
        if proc[0] is not None:
            try:
                proc[0].send_signal(signum)
            except OSError:
                pass

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        proc[0] = subprocess.Popen(*args, **kwargs)
        return proc[0].wait()
    finally:
        signal.signal(signal.SIGINT, signal.default_int_handler)
