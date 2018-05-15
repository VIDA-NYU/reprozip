# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Packing logic for reprozip.

This module contains the :func:`~reprozip.pack.pack` function and associated
utilities that are used to build the .rpz pack file from the trace SQLite file
and config YAML.
"""

from __future__ import division, print_function, unicode_literals

import itertools
import logging
import os
from rpaths import Path
import string
import sys
import tarfile
import uuid

from reprozip import __version__ as reprozip_version
from reprozip.common import File, load_config, save_config, \
    record_usage_package
from reprozip.tracer.linux_pkgs import identify_packages
from reprozip.traceutils import combine_files
from reprozip.utils import iteritems


logger = logging.getLogger('reprozip')


def expand_patterns(patterns):
    files = set()
    dirs = set()

    # Finds all matching paths
    for pattern in patterns:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Expanding pattern %r into %d paths",
                         pattern,
                         len(list(Path('/').recursedir(pattern))))
        for path in Path('/').recursedir(pattern):
            if path.is_dir():
                dirs.add(path)
            else:
                files.add(path)

    # Don't include directories whose files are included
    non_empty_dirs = set([Path('/')])
    for p in files | dirs:
        path = Path('/')
        for c in p.components[1:]:
            path = path / c
            non_empty_dirs.add(path)

    # Builds the final list
    return [File(p) for p in itertools.chain(dirs - non_empty_dirs, files)]


def canonicalize_config(packages, other_files, additional_patterns,
                        sort_packages):
    """Expands ``additional_patterns`` from the configuration file.
    """
    if additional_patterns:
        add_files = expand_patterns(additional_patterns)
        logger.info("Found %d files from expanding additional_patterns...",
                    len(add_files))
        if add_files:
            if sort_packages:
                add_files, add_packages = identify_packages(add_files)
            else:
                add_packages = []
            other_files, packages = combine_files(add_files, add_packages,
                                                  other_files, packages)
    return packages, other_files


def data_path(filename, prefix=Path('DATA')):
    """Computes the filename to store in the archive.

    Turns an absolute path containing '..' into a filename without '..', and
    prefixes with DATA/.

    Example:

    >>> data_path(PosixPath('/var/lib/../../../../tmp/test'))
    PosixPath(b'DATA/tmp/test')
    >>> data_path(PosixPath('/var/lib/../www/index.html'))
    PosixPath(b'DATA/var/www/index.html')
    """
    return prefix / filename.split_root()[1]


class PackBuilder(object):
    """Higher layer on tarfile that adds intermediate directories.
    """
    def __init__(self, filename):
        self.tar = tarfile.open(str(filename), 'w:gz')
        self.seen = set()

    def add_data(self, filename):
        if filename in self.seen:
            return
        path = Path('/')
        for c in filename.components[1:]:
            path = path / c
            if path in self.seen:
                continue
            logger.debug("%s -> %s", path, data_path(path))
            self.tar.add(str(path), str(data_path(path)), recursive=False)
            self.seen.add(path)

    def close(self):
        self.tar.close()
        self.seen = None


def pack(target, directory, sort_packages):
    """Main function for the pack subcommand.
    """
    if target.exists():
        # Don't overwrite packs...
        logger.critical("Target file exists!")
        sys.exit(1)

    # Reads configuration
    configfile = directory / 'config.yml'
    if not configfile.is_file():
        logger.critical("Configuration file does not exist!\n"
                        "Did you forget to run 'reprozip trace'?\n"
                        "If not, you might want to use --dir to specify an "
                        "alternate location.")
        sys.exit(1)
    runs, packages, other_files = config = load_config(
        configfile,
        canonical=False)
    additional_patterns = config.additional_patterns
    inputs_outputs = config.inputs_outputs

    # Validate run ids
    run_chars = ('0123456789_-@() .:%'
                 'abcdefghijklmnopqrstuvwxyz'
                 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    for i, run in enumerate(runs):
        if (any(c not in run_chars for c in run['id']) or
                all(c in string.digits for c in run['id'])):
            logger.critical("Illegal run id: %r (run number %d)",
                            run['id'], i)
            sys.exit(1)

    # Canonicalize config (re-sort, expand 'additional_files' patterns)
    packages, other_files = canonicalize_config(
        packages, other_files, additional_patterns, sort_packages)

    logger.info("Creating pack %s...", target)
    tar = tarfile.open(str(target), 'w:')

    fd, tmp = Path.tempfile()
    os.close(fd)
    try:
        datatar = PackBuilder(tmp)
        # Add the files from the packages
        for pkg in packages:
            if pkg.packfiles:
                logger.info("Adding files from package %s...", pkg.name)
                files = []
                for f in pkg.files:
                    if not Path(f.path).exists():
                        logger.warning("Missing file %s from package %s",
                                       f.path, pkg.name)
                    else:
                        datatar.add_data(f.path)
                        files.append(f)
                pkg.files = files
            else:
                logger.info("NOT adding files from package %s", pkg.name)

        # Add the rest of the files
        logger.info("Adding other files...")
        files = set()
        for f in other_files:
            if not Path(f.path).exists():
                logger.warning("Missing file %s", f.path)
            else:
                datatar.add_data(f.path)
                files.add(f)
        other_files = files
        datatar.close()

        tar.add(str(tmp), 'DATA.tar.gz')
    finally:
        tmp.remove()

    logger.info("Adding metadata...")
    # Stores pack version
    fd, manifest = Path.tempfile(prefix='reprozip_', suffix='.txt')
    os.close(fd)
    try:
        with manifest.open('wb') as fp:
            fp.write(b'REPROZIP VERSION 2\n')
        tar.add(str(manifest), 'METADATA/version')
    finally:
        manifest.remove()

    # Stores the original trace
    trace = directory / 'trace.sqlite3'
    if not trace.is_file():
        logger.critical("trace.sqlite3 is gone! Aborting")
        sys.exit(1)
    tar.add(str(trace), 'METADATA/trace.sqlite3')

    # Checks that input files are packed
    for name, f in iteritems(inputs_outputs):
        if f.read_runs and not Path(f.path).exists():
            logger.warning("File is designated as input (name %s) but is not "
                           "to be packed: %s", name, f.path)

    # Generates a unique identifier for the pack (for usage reports purposes)
    pack_id = str(uuid.uuid4())

    # Stores canonical config
    fd, can_configfile = Path.tempfile(suffix='.yml', prefix='rpz_config_')
    os.close(fd)
    try:
        save_config(can_configfile, runs, packages, other_files,
                    reprozip_version,
                    inputs_outputs, canonical=True,
                    pack_id=pack_id)

        tar.add(str(can_configfile), 'METADATA/config.yml')
    finally:
        can_configfile.remove()

    tar.close()

    # Record some info to the usage report
    record_usage_package(runs, packages, other_files,
                         inputs_outputs,
                         pack_id)
