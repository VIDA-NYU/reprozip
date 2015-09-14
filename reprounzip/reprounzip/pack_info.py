# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Entry point for the reprounzip utility.

This contains :func:`~reprounzip.reprounzip.main`, which is the entry point
declared to setuptools. It is also callable directly.

It dispatchs to plugins registered through pkg_resources as entry point
``reprounzip.unpackers``.
"""

from __future__ import division, print_function, unicode_literals

import argparse
import logging
import platform
from rpaths import Path
import sys

from reprounzip.common import RPZPack, load_config as load_config_file
from reprounzip.main import unpackers
from reprounzip.unpackers.common import load_config, COMPAT_OK, COMPAT_MAYBE, \
    COMPAT_NO, UsageError, shell_escape, metadata_read
from reprounzip.utils import iteritems, itervalues, unicode_, hsize


def print_info(args):
    """Writes out some information about a pack file.
    """
    pack = Path(args.pack[0])

    # Loads config
    runs, packages, other_files = config = load_config(pack)
    inputs_outputs = config.inputs_outputs

    pack_total_size = 0
    pack_total_paths = 0
    pack_files = 0
    pack_dirs = 0
    pack_symlinks = 0
    pack_others = 0
    rpz_pack = RPZPack(pack)
    for m in rpz_pack.list_data():
        pack_total_size += m.size
        pack_total_paths += 1
        if m.isfile():
            pack_files += 1
        elif m.isdir():
            pack_dirs += 1
        elif m.issym():
            pack_symlinks += 1
        else:
            pack_others += 1
    rpz_pack.close()

    meta_total_paths = 0
    meta_packed_packages_files = 0
    meta_unpacked_packages_files = 0
    meta_packages = len(packages)
    meta_packed_packages = 0
    for package in packages:
        nb = len(package.files)
        meta_total_paths += nb
        if package.packfiles:
            meta_packed_packages_files += nb
            meta_packed_packages += 1
        else:
            meta_unpacked_packages_files += nb
    nb = len(other_files)
    meta_total_paths += nb
    meta_packed_paths = meta_packed_packages_files + nb

    if runs:
        meta_architecture = runs[0]['architecture']
        if any(r['architecture'] != meta_architecture
               for r in runs):
            logging.warning("Runs have different architectures")
        meta_distribution = runs[0]['distribution']
        if any(r['distribution'] != meta_distribution
               for r in runs):
            logging.warning("Runs have different distributions")
        meta_distribution = ' '.join(t for t in meta_distribution if t)

    current_architecture = platform.machine().lower()
    current_distribution = platform.linux_distribution()[0:2]
    current_distribution = ' '.join(t for t in current_distribution if t)

    print("Pack file: %s" % pack)
    print("\n----- Pack information -----")
    print("Compressed size: %s" % hsize(pack.size()))
    print("Unpacked size: %s" % hsize(pack_total_size))
    print("Total packed paths: %d" % pack_total_paths)
    if args.verbosity >= 3:
        print("    Files: %d" % pack_files)
        print("    Directories: %d" % pack_dirs)
        print("    Symbolic links: %d" % pack_symlinks)
    if pack_others:
        print("    Unknown (what!?): %d" % pack_others)
    print("\n----- Metadata -----")
    if args.verbosity >= 3:
        print("Total paths: %d" % meta_total_paths)
        print("Listed packed paths: %d" % meta_packed_paths)
    if packages:
        print("Total software packages: %d" % meta_packages)
        print("Packed software packages: %d" % meta_packed_packages)
        if args.verbosity >= 3:
            print("Files from packed software packages: %d" %
                  meta_packed_packages_files)
            print("Files from unpacked software packages: %d" %
                  meta_unpacked_packages_files)
    if runs:
        print("Architecture: %s (current: %s)" % (meta_architecture,
                                                  current_architecture))
        print("Distribution: %s (current: %s)" % (
              meta_distribution, current_distribution or "(not Linux)"))
        print("Runs (%d):" % len(runs))
        for i, run in enumerate(runs):
            cmdline = ' '.join(shell_escape(a) for a in run['argv'])
            if len(runs) == 1 and run['id'] == "run0":
                print("    %s" % cmdline)
            else:
                print("    %s: %s" % (run['id'], cmdline))
            if args.verbosity >= 2:
                print("        wd: %s" % run['workingdir'])
                if 'signal' in run:
                    print("        signal: %d" % run['signal'])
                else:
                    print("        exitcode: %d" % run['exitcode'])

    if inputs_outputs:
        if args.verbosity < 2:
            print("Inputs/outputs files (%d): %s" % (
                  len(inputs_outputs), ", ".join(sorted(inputs_outputs))))
        else:
            print("Inputs/outputs files (%d):" % len(inputs_outputs))
            for name, f in sorted(iteritems(inputs_outputs)):
                t = []
                if f.read_runs:
                    t.append("in")
                if f.write_runs:
                    t.append("out")
                print("    %s (%s): %s" % (name, ' '.join(t), f.path))

    # Unpacker compatibility
    print("\n----- Unpackers -----")
    unpacker_status = {}
    for name, upk in iteritems(unpackers):
        if 'test_compatibility' in upk:
            compat = upk['test_compatibility']
            if callable(compat):
                compat = compat(pack, config=config)
            if isinstance(compat, (tuple, list)):
                compat, msg = compat
            else:
                msg = None
            unpacker_status.setdefault(compat, []).append((name, msg))
        else:
            unpacker_status.setdefault(None, []).append((name, None))
    for s, n in [(COMPAT_OK, "Compatible"), (COMPAT_MAYBE, "Unknown"),
                 (COMPAT_NO, "Incompatible")]:
        if s != COMPAT_OK and args.verbosity < 2:
            continue
        if s not in unpacker_status:
            continue
        upks = unpacker_status[s]
        print("%s (%d):" % (n, len(upks)))
        for upk_name, msg in upks:
            if msg is not None:
                print("    %s (%s)" % (upk_name, msg))
            else:
                print("    %s" % upk_name)


def showfiles(args):
    """Writes out the input and output files.

    Works both for a pack file and for an extracted directory.
    """
    def parse_run(runs, s):
        for i, run in enumerate(runs):
            if run['id'] == s:
                return i
        else:
            try:
                r = int(s)
            except ValueError:
                logging.critical("Error: Unknown run %s", s)
                raise UsageError
            if r < 0 or r >= len(runs):
                logging.critical("Error: Expected 0 <= run <= %d, got %d",
                                 len(runs) - 1, r)
                sys.exit(1)
            return r

    def file_filter(fio):
        if file_filter.run is None:
            return True
        else:
            return (file_filter.run in fio.read_runs or
                    file_filter.run in fio.write_runs)

    file_filter.run = None

    pack = Path(args.pack[0])

    if not pack.exists():
        logging.critical("Pack or directory %s does not exist", pack)
        sys.exit(1)

    if pack.is_dir():
        # Reads info from an unpacked directory
        config = load_config_file(pack / 'config.yml',
                                  canonical=True)

        # Filter files by run
        if args.run is not None:
            file_filter.run = parse_run(config.runs, args.run)

        # The '.reprounzip' file is a pickled dictionary, it contains the name
        # of the files that replaced each input file (if upload was used)
        unpacked_info = metadata_read(pack, None)
        assigned_input_files = unpacked_info.get('input_files', {})

        if any(f.read_runs for f in itervalues(config.inputs_outputs)):
            print("Input files:")
            for input_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.read_runs and file_filter(f):
                    if args.verbosity >= 2:
                        print("    %s (%s)" % (input_name, f.path))
                    else:
                        print("    %s" % input_name)

                    assigned = assigned_input_files.get(input_name)
                    if assigned is None:
                        assigned = "(original)"
                    elif assigned is False:
                        assigned = "(not created)"
                    elif assigned is True:
                        assigned = "(generated)"
                    else:
                        assert isinstance(assigned, (bytes, unicode_))
                    print("      %s" % assigned)
        else:
            print("Input files: none")

        if any(f.write_runs for f in itervalues(config.inputs_outputs)):
            print("Output files:")
            for output_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.write_runs and file_filter(f):
                    if args.verbosity >= 2:
                        print("    %s (%s)" % (output_name, f.path))
                    else:
                        print("    %s" % output_name)
        else:
            print("Output files: none")

    else:  # pack.is_file()
        # Reads info from a pack file
        config = load_config(pack)

        # Filter files by run
        if args.run is not None:
            file_filter.run = parse_run(config.runs, args.run)

        if any(f.read_runs for f in itervalues(config.inputs_outputs)):
            print("Input files:")
            for input_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.read_runs and file_filter(f):
                    if args.verbosity >= 2:
                        print("    %s (%s)" % (input_name, f.path))
                    else:
                        print("    %s" % input_name)
        else:
            print("Input files: none")

        if any(f.write_runs for f in itervalues(config.inputs_outputs)):
            print("Output files:")
            for output_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.write_runs and file_filter(f):
                    if args.verbosity >= 2:
                        print("    %s (%s)" % (output_name, f.path))
                    else:
                        print("    %s" % output_name)
        else:
            print("Output files: none")


def setup_info(parser, **kwargs):
    """Prints out some information about a pack
    """
    parser.add_argument('pack', nargs=1,
                        help="Pack to read")
    parser.set_defaults(func=print_info)


def setup_showfiles(parser, **kwargs):
    """Prints out input and output file names
    """
    parser.add_argument('pack', nargs=1,
                        help="Pack or directory to read from")
    parser.add_argument('run', nargs=argparse.OPTIONAL,
                        help="Run whose input and output files will be listed")
    parser.set_defaults(func=showfiles)
