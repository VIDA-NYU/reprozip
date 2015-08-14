# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Miscellaneous utilities for unpacker plugins.
"""

from __future__ import division, print_function, unicode_literals

import copy
import functools
import logging
import os
import random
from rpaths import PosixPath, Path
import signal
import subprocess
import sys
import tarfile

import reprounzip.common
from reprounzip.utils import irange, iteritems, stdout_bytes


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


safe_shell_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       "-+=/:.,%_")


def shell_escape(s):
    """Given bl"a, returns "bl\\"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if any(c not in safe_shell_chars for c in s):
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


def sudo_url(arch):
    """Gets the correct URL for the rpzsudo binary given the architecture.
    """
    return ('https://github.com/remram44/static-sudo'
            '/releases/download/current/rpzsudo-%s' % arch)


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
        input_files = dict(
            (n, f.path)
            for n, f in iteritems(self.get_config().inputs_outputs)
            if f.read_runs)

        # No argument: list all the input files and exit
        if not files:
            print("Input files:")
            for input_name in input_files:
                if self.input_files.get(input_name) is not None:
                    assigned = self.input_files[input_name]
                else:
                    assigned = "(original)"
                print("    %s: %s" % (input_name, assigned))
            return

        self.prepare_upload(files)

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
                    input_path = input_files[input_name]
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
                    if local_path is None:
                        temp.remove()
                        logging.warning("No original packed, can't restore "
                                        "input file %s", input_name)
                        continue
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

    def get_config(self):
        return reprounzip.common.load_config(self.target / 'config.yml',
                                             canonical=True)

    def prepare_upload(self, files):
        pass

    def extract_original_input(self, input_name, input_path, temp):
        tar = tarfile.open(str(self.target / 'experiment.rpz'), 'r:*')
        try:
            member = tar.getmember(str(join_root(PosixPath('DATA'),
                                                 input_path)))
        except KeyError:
            return None
        member = copy.copy(member)
        member.name = str(temp.components[-1])
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
        output_files = dict(
            (n, f.path)
            for n, f in iteritems(self.get_config().inputs_outputs)
            if f.write_runs)

        # No argument: list all the output files and exit
        if not files:
            print("Output files:")
            for output_name in output_files:
                print("    %s" % output_name)
            return

        self.prepare_download(files)

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
                    remote_path = output_files[output_name]
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

    def get_config(self):
        return reprounzip.common.load_config(self.target / 'config.yml',
                                             canonical=True)

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
                stdout_bytes.write(chunk)
            while len(chunk) == 1024:
                chunk = fp.read(1024)
                if chunk:
                    stdout_bytes.write(chunk)
        temp.remove()

    def download(self, remote_path, local_path):
        raise NotImplementedError

    def finalize(self):
        pass


def get_runs(runs, selected_runs, cmdline):
    """Selects which run(s) to execute based on parts of the command-line.

    Will return an iterable of run numbers. Might also fail loudly or exit
    after printing the original command-line.
    """
    if selected_runs is None:
        if len(runs) == 1:
            selected_runs = '0'
        else:
            logging.critical("There are several runs in this pack -- you have "
                             "to choose which one to use")
            sys.exit(1)

    def parse_run(s):
        try:
            r = int(s)
        except ValueError:
            logging.critical("Error: Run is not a number")
            raise UsageError
        if r < 0 or r >= len(runs):
            logging.critical("Error: Expected 0 <= run <= %d, got %d",
                             len(runs) - 1, r)
            sys.exit(1)
        return r

    sep = selected_runs.find('-')
    if sep == -1:
        selected_runs = parse_run(selected_runs),
    else:
        if sep > 0:
            first = parse_run(selected_runs[:sep])
        else:
            first = 0
        if sep + 1 < len(selected_runs):
            last = parse_run(selected_runs[sep + 1:])
        else:
            last = len(runs) - 1
        if last <= first:
            logging.critical("Error: Last run number should be greater than "
                             "the first")
            sys.exit(1)
        selected_runs = irange(first, last + 1)

    # --cmdline without arguments: display the original command-line
    if cmdline == []:
        print("Original command-lines:")
        for run in selected_runs:
            print(' '.join(shell_escape(arg)
                           for arg in runs[run]['argv']))
        sys.exit(0)

    return selected_runs


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
