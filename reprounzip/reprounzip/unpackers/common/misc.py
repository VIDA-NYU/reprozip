# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Miscellaneous utilities for unpacker plugins.
"""

import copy
import functools
import logging
import itertools
import os
import pickle
import pkg_resources
import random
import re
from rpaths import PosixPath, Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import warnings

import reprozip_core.common
from reprozip_core.common import RPZPack
from reprounzip.parameters import get_parameter
from reprozip_core.utils import join_root


logger = logging.getLogger('reprounzip')


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
            logger.critical("Error: Target directory doesn't exist")
            raise UsageError
        return func(args)
    return wrapper


def unique_names():
    """Generates unique sequences of bytes.
    """
    characters = (b"abcdefghijklmnopqrstuvwxyz"
                  b"0123456789")
    characters = [characters[i:i + 1] for i in range(len(characters))]
    rng = random.Random()
    while True:
        letters = [rng.choice(characters) for i in range(10)]
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
    r"""Given bl"a, returns "bl\\"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if not s or any(c not in safe_shell_chars for c in s):
        return '"%s"' % (s.replace('\\', '\\\\')
                          .replace('"', '\\"')
                          .replace('`', '\\`')
                          .replace('$', '\\$'))
    else:
        return s


def load_config(pack):
    """Utility method loading the YAML configuration from inside a pack file.

    Decompresses the config.yml file from the tarball to a temporary file then
    loads it. Note that decompressing a single file is inefficient, thus
    calling this method can be slow.
    """
    rpz_pack = RPZPack(pack)
    with rpz_pack.with_config() as configfile:
        return reprozip_core.common.load_config(configfile, canonical=True)


def busybox_url(arch):
    """Gets the correct URL for the busybox binary given the architecture.
    """
    return get_parameter('busybox_url')[arch]


def rpzsudo_binary(arch):
    """Gets the rpzsudo file given the architecture.
    """
    return pkg_resources.resource_stream(
        __name__.split('.', 1)[0],
        'rpzsudo-%s' % arch,
    )


def rpztar_url(arch):
    """Gets the correct URL for the rpztar binary given the architecture.
    """
    return get_parameter('rpztar_url')[arch]


class FileUploader(object):
    """Common logic for 'upload' commands.
    """
    data_tgz = 'data.tgz'

    def __init__(self, target, input_files, files):
        self.target = target
        self.input_files = input_files
        self.run(files)

    def run(self, files):
        reprozip_core.common.record_usage(upload_files=len(files))
        inputs_outputs = self.get_config().inputs_outputs

        # No argument: list all the input files and exit
        if not files:
            print("Input files:")
            for input_name in sorted(n for n, f in inputs_outputs.items()
                                     if f.read_runs):
                assigned = self.input_files.get(input_name)
                if assigned is None:
                    assigned = "(original)"
                elif assigned is False:
                    assigned = "(not created)"
                elif assigned is True:
                    assigned = "(generated)"
                else:
                    assert isinstance(assigned, (bytes, str))
                print("    %s: %s" % (input_name, assigned))
            return

        self.prepare_upload(files)

        try:
            # Upload files
            for filespec in files:
                filespec_split = filespec.rsplit(':', 1)
                if len(filespec_split) != 2:
                    logger.critical("Invalid file specification: %r",
                                    filespec)
                    sys.exit(1)
                local_path, input_name = filespec_split

                if input_name.startswith('/'):
                    input_path = PurePosixPath(input_name)
                else:
                    try:
                        input_path = inputs_outputs[input_name].path
                    except KeyError:
                        logger.critical("Invalid input file: %r", input_name)
                        sys.exit(1)

                temp = None

                if not local_path:
                    # Restore original file from pack
                    logger.debug("Restoring input file %s", input_path)
                    fd, temp = tempfile.mkstemp(prefix='reprozip_input_')
                    temp = Path(temp)
                    os.close(fd)
                    local_path = self.extract_original_input(input_name,
                                                             input_path,
                                                             temp)
                    if local_path is None:
                        temp.unlink()
                        logger.warning("No original packed, can't restore "
                                       "input file %s", input_name)
                        continue
                else:
                    local_path = Path(local_path)
                    logger.debug("Uploading file %s to %s",
                                 local_path, input_path)
                    if not local_path.exists():
                        logger.critical("Local file %s doesn't exist",
                                        local_path)
                        sys.exit(1)

                self.upload_file(local_path, input_path)

                if temp is not None:
                    temp.unlink()
                    self.input_files.pop(input_name, None)
                else:
                    self.input_files[input_name] = local_path.absolute().path
        finally:
            self.finalize()

    def get_config(self):
        return reprozip_core.common.load_config(self.target / 'config.yml',
                                                canonical=True)

    def prepare_upload(self, files):
        pass

    def extract_original_input(self, input_name, input_path, temp):
        tar = tarfile.open(str(self.target / self.data_tgz), 'r:*')
        try:
            member = tar.getmember(str(join_root(PurePosixPath('DATA'),
                                                 input_path)))
        except KeyError:
            return None
        member = copy.copy(member)
        member.name = str(temp.parts[-1])
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
    def __init__(self, target, files, all_=False):
        self.target = target
        self.run(files, all_)

    def run(self, files, all_):
        reprozip_core.common.record_usage(download_files=len(files))
        inputs_outputs = self.get_config().inputs_outputs

        # No argument: list all the output files and exit
        if not (all_ or files):
            print("Output files:")
            for output_name in sorted(n for n, f in inputs_outputs.items()
                                      if f.write_runs):
                print("    %s" % output_name)
            return

        # Parse the name[:path] syntax
        resolved_files = []
        all_files = set(n for n, f in inputs_outputs.items()
                        if f.write_runs)
        for filespec in files:
            filespec_split = filespec.split(':', 1)
            if len(filespec_split) == 1:
                output_name = local_path = filespec
            elif len(filespec_split) == 2:
                output_name, local_path = filespec_split
            else:
                logger.critical("Invalid file specification: %r",
                                filespec)
                sys.exit(1)
            local_path = Path(local_path) if local_path else None
            all_files.discard(output_name)
            resolved_files.append((output_name, local_path))

        # If all_ is set, add all the files that weren't explicitely named
        if all_:
            for output_name in all_files:
                resolved_files.append((output_name, Path(output_name)))

        self.prepare_download(resolved_files)

        success = True
        try:
            # Download files
            for output_name, local_path in resolved_files:
                if output_name.startswith('/'):
                    remote_path = PurePosixPath(output_name)
                else:
                    try:
                        remote_path = inputs_outputs[output_name].path
                    except KeyError:
                        logger.critical("Invalid output file: %r",
                                        output_name)
                        sys.exit(1)

                logger.debug("Downloading file %s", remote_path)
                if local_path is None:
                    ret = self.download_and_print(remote_path)
                else:
                    ret = self.download(remote_path, local_path)
                if ret is None:
                    ret = True
                    warnings.warn("download() returned None instead of "
                                  "True/False, assuming True",
                                  category=DeprecationWarning)
                if not ret:
                    success = False
            if not success:
                sys.exit(1)
        finally:
            self.finalize()

    def get_config(self):
        return reprozip_core.common.load_config(self.target / 'config.yml',
                                                canonical=True)

    def prepare_download(self, files):
        pass

    def download_and_print(self, remote_path):
        # Download to temporary file
        fd, temp = tempfile.mkstemp(prefix='reprozip_output_')
        temp = Path(temp)
        os.close(fd)
        download_status = self.download(remote_path, temp)
        if download_status is not None and not download_status:
            return False
        # Output to stdout
        with temp.open('rb') as fp:
            shutil.copyfileobj(fp, sys.stdout.buffer)
        temp.unlink()
        return True

    def download(self, remote_path, local_path):
        raise NotImplementedError

    def finalize(self):
        pass


def get_runs(runs, selected_runs, cmdline):
    """Selects which run(s) to execute based on parts of the command-line.

    Will return an iterable of run numbers. Might also fail loudly or exit
    after printing the original command-line.
    """
    name_map = dict((r['id'], i) for i, r in enumerate(runs) if 'id' in r)
    run_list = []

    def parse_run(s):
        try:
            r = int(s)
        except ValueError:
            logger.critical("Error: Unknown run %s", s)
            raise UsageError
        if r < 0 or r >= len(runs):
            logger.critical("Error: Expected 0 <= run <= %d, got %d",
                            len(runs) - 1, r)
            sys.exit(1)
        return r

    if selected_runs is None:
        run_list = list(range(len(runs)))
    else:
        for run_item in selected_runs.split(','):
            run_item = run_item.strip()
            if run_item in name_map:
                run_list.append(name_map[run_item])
                continue

            sep = run_item.find('-')
            if sep == -1:
                run_list.append(parse_run(run_item))
            else:
                if sep > 0:
                    first = parse_run(run_item[:sep])
                else:
                    first = 0
                if sep + 1 < len(run_item):
                    last = parse_run(run_item[sep + 1:])
                else:
                    last = len(runs) - 1
                if last < first:
                    logger.critical("Error: Last run number should be "
                                    "greater than the first")
                    sys.exit(1)
                run_list.extend(range(first, last + 1))

    # --cmdline without arguments: display the original command-line
    if cmdline == []:
        print("Original command-lines:")
        for run in run_list:
            print(' '.join(shell_escape(arg)
                           for arg in runs[run]['argv']))
        sys.exit(0)

    return run_list


def add_environment_options(parser):
    parser.add_argument('--pass-env', action='append', default=[],
                        help="Environment variable to pass through from the "
                             "host (value from the original machine will be "
                             "overridden; can be passed multiple times)")
    parser.add_argument('--set-env', action='append', default=[],
                        help="Environment variable to set (value from the "
                             "original machine will be ignored; can be passed "
                             "multiple times)")


def parse_environment_args(args):
    if not (args.pass_env or args.set_env):
        return {}, []

    env_set = {}
    env_unset = []

    regexes = [re.compile(pattern + '$') for pattern in args.pass_env]
    for var in os.environ:
        if any(regex.match(var) for regex in regexes):
            env_set[var] = os.environ[var]

    for var in args.set_env:
        if '=' in var:
            var, value = var.split('=', 1)
            env_set[var] = value
        else:
            env_unset.append(var)

    return env_set, env_unset


def fixup_environment(environ, args):
    env_set, env_unset = parse_environment_args(args)
    if env_set or env_unset:
        environ = dict(environ)
        environ.update(env_set)
        for k in env_unset:
            environ.pop(k, None)
    return environ


def pty_spawn(*args, **kwargs):
    import pty

    return pty.spawn(*args, **kwargs)


def interruptible_call(cmd, **kwargs):
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
        if kwargs.pop('request_tty', False):
            try:
                import pty  # noqa: F401
            except ImportError:
                pass
            else:
                if hasattr(sys.stdin, 'isatty') and not sys.stdin.isatty():
                    logger.info("We need a tty and we are not attached to "
                                "one. Opening pty...")
                    if kwargs.pop('shell', False):
                        if not isinstance(cmd, (str, str)):
                            raise TypeError("shell=True but cmd is not a "
                                            "string")
                        cmd = ['/bin/sh', '-c', cmd]
                    res = pty_spawn(cmd)
                    return res >> 8 - (res & 0xFF)
        proc[0] = subprocess.Popen(cmd, **kwargs)
        return proc[0].wait()
    finally:
        signal.signal(signal.SIGINT, signal.default_int_handler)


def metadata_read(path, type_):
    """Read the unpacker-specific metadata from an unpacked directory.

    :param path: The unpacked directory; `.reprounzip` will be appended to get
    the name of the pickle file.
    :param type_: The name of the unpacker, to check for consistency.

    Unpackers need to store some specific information, along with the status of
    the input files. This is done in a consistent way so that showfiles can
    access it (and because duplicating code is not necessary here).

    It's a simple pickled dictionary under path / '.reprounzip'. The
    'input_files' key stores the status of the input files.

    If you change it, don't forget to call `metadata_write` to write it to disk
    again.
    """
    filename = path / '.reprounzip'

    if not filename.exists():
        logger.critical("Required metadata missing, did you point this "
                        "command at the directory you created using the "
                        "'setup' command?")
        raise UsageError
    with filename.open('rb') as fp:
        dct = pickle.load(fp)
    if type_ is not None and dct['unpacker'] != type_:
        logger.critical("Wrong unpacker used: %s != %s",
                        dct['unpacker'], type_)
        raise UsageError
    return dct


def metadata_write(path, dct, type_):
    """Write the unpacker-specific metadata in an unpacked directory.

    :param path: The unpacked directory; `.reprounzip` will be appended to get
    the name of the pickle file.
    :param type_: The name of the unpacker, that is written to the pickle file
    under the key 'unpacker'.
    :param dct: The dictionary with the info to write to the file.
    """
    filename = path / '.reprounzip'

    to_write = {'unpacker': type_}
    to_write.update(dct)
    with filename.open('wb') as fp:
        pickle.dump(to_write, fp, 2)


def metadata_initial_iofiles(config, dct=None):
    """Add the initial state of the {in/out}put files to the unpacker metadata.

    :param config: The configuration as returned by `load_config()`, which will
    be used to list the input and output files and to determine which ones have
    been packed (and therefore exist initially).

    The `input_files` key contains a dict mapping the name to either:
      * None (or inexistent): original file and exists
      * False: doesn't exist (wasn't packed)
      * True: has been generated by one of the run since the experiment was
        unpacked
      * basestring: the user uploaded a file with this path, and no run has
        overwritten it yet
    """
    if dct is None:
        dct = {}

    path2iofile = {f.path: n
                   for n, f in config.inputs_outputs.items()}

    def packed_files():
        yield config.other_files
        for pkg in config.packages:
            if pkg.packfiles:
                yield pkg.files

    for f in itertools.chain.from_iterable(packed_files()):
        f = f.path
        path2iofile.pop(f, None)

    dct['input_files'] = dict((n, False) for n in path2iofile.values())

    return dct


def metadata_update_run(config, dct, runs):
    """Update the unpacker metadata after some runs have executed.

    :param runs: An iterable of run numbers that were probably executed.

    This maintains a crude idea of the status of input and output files by
    updating the files that are outputs of the runs that were just executed.
    This means that files that were uploaded by the user will no longer be
    shown as uploaded (they have been overwritten by the experiment) and files
    that weren't packed exist from now on.

    This is not very reliable because a run might have created a file that is
    not designated as its output anyway, or might have failed and thus not
    created the output (or a bad output).
    """
    runs = set(runs)
    input_files = dct.setdefault('input_files', {})

    for name, fi in config.inputs_outputs.items():
        if any(r in runs for r in fi.write_runs):
            input_files[name] = True


_port_re = re.compile('^(?:([0-9]+):)?([0-9]+)(?:/([a-z]+))?$')


def parse_ports(specifications):
    ports = []

    for port in specifications:
        m = _port_re.match(port)
        if m is None:
            logger.critical("Invalid port specification: '%s'", port)
            sys.exit(1)
        host, experiment, proto = m.groups()
        if not host:
            host = experiment
        if not proto:
            proto = 'tcp'
        ports.append((int(host), int(experiment), proto))

    return ports
