# Copyright (C) 2014-2017 New York University
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
import json
import logging
import platform
from rpaths import Path
import sys

from reprounzip.common import RPZPack, load_config as load_config_file
from reprounzip.main import unpackers
from reprounzip.unpackers.common import load_config, COMPAT_OK, COMPAT_MAYBE, \
    COMPAT_NO, UsageError, shell_escape, metadata_read
from reprounzip.utils import iteritems, itervalues, unicode_, hsize


def get_package_info(pack, read_data=False):
    """Get information about a package.
    """
    runs, packages, other_files = config = load_config(pack)
    inputs_outputs = config.inputs_outputs

    information = {}

    if read_data:
        total_size = 0
        total_paths = 0
        files = 0
        dirs = 0
        symlinks = 0
        hardlinks = 0
        others = 0

        rpz_pack = RPZPack(pack)
        for m in rpz_pack.list_data():
            total_size += m.size
            total_paths += 1
            if m.isfile():
                files += 1
            elif m.isdir():
                dirs += 1
            elif m.issym():
                symlinks += 1
            elif hasattr(m, 'islnk') and m.islnk():
                hardlinks += 1
            else:
                others += 1
        rpz_pack.close()

        information['pack'] = {
            'total_size': total_size,
            'total_paths': total_paths,
            'files': files,
            'dirs': dirs,
            'symlinks': symlinks,
            'hardlinks': hardlinks,
            'others': others,
        }

    total_paths = 0
    packed_packages_files = 0
    unpacked_packages_files = 0
    packed_packages = 0
    for package in packages:
        nb = len(package.files)
        total_paths += nb
        if package.packfiles:
            packed_packages_files += nb
            packed_packages += 1
        else:
            unpacked_packages_files += nb
    nb = len(other_files)
    total_paths += nb

    information['meta'] = {
        'total_paths': total_paths,
        'packed_packages_files': packed_packages_files,
        'unpacked_packages_files': unpacked_packages_files,
        'packages': len(packages),
        'packed_packages': packed_packages,
        'packed_paths': packed_packages_files + nb,
    }

    if runs:
        architecture = runs[0]['architecture']
        if any(r['architecture'] != architecture
               for r in runs):
            logging.warning("Runs have different architectures")
        information['meta']['architecture'] = architecture
        distribution = runs[0]['distribution']
        if any(r['distribution'] != distribution
               for r in runs):
            logging.warning("Runs have different distributions")
        information['meta']['distribution'] = distribution

        information['runs'] = [
            dict((k, run[k])
                 for k in ['id', 'binary', 'argv', 'environ',
                           'workingdir', 'signal', 'exitcode']
                 if k in run)
            for run in runs]

    information['inputs_outputs'] = {
        name: {'path': str(iofile.path),
               'read_runs': iofile.read_runs,
               'write_runs': iofile.write_runs}
        for name, iofile in iteritems(inputs_outputs)}

    # Unpacker compatibility
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
    information['unpacker_status'] = unpacker_status

    return information


def _print_package_info(pack, info, verbosity=1):
    print("Pack file: %s" % pack)
    print("\n----- Pack information -----")
    print("Compressed size: %s" % hsize(pack.size()))

    info_pack = info.get('pack')
    if info_pack:
        if 'total_size' in info_pack:
            print("Unpacked size: %s" % hsize(info_pack['total_size']))
        if 'total_paths' in info_pack:
            print("Total packed paths: %d" % info_pack['total_paths'])
        if verbosity >= 3:
            print("    Files: %d" % info_pack['files'])
            print("    Directories: %d" % info_pack['dirs'])
            if info_pack.get('symlinks'):
                print("    Symbolic links: %d" % info_pack['symlinks'])
            if info_pack.get('hardlinks'):
                print("    Hard links: %d" % info_pack['hardlinks'])
        if info_pack.get('others'):
            print("    Unknown (what!?): %d" % info_pack['others'])
    print("\n----- Metadata -----")
    info_meta = info['meta']
    if verbosity >= 3:
        print("Total paths: %d" % info_meta['total_paths'])
        print("Listed packed paths: %d" % info_meta['packed_paths'])
    if info_meta.get('packages'):
        print("Total software packages: %d" % info_meta['packages'])
        print("Packed software packages: %d" % info_meta['packed_packages'])
        if verbosity >= 3:
            print("Files from packed software packages: %d" %
                  info_meta['packed_packages_files'])
            print("Files from unpacked software packages: %d" %
                  info_meta['unpacked_packages_files'])
    if 'architecture' in info_meta:
        print("Architecture: %s (current: %s)" % (info_meta['architecture'],
                                                  platform.machine().lower()))
    if 'distribution' in info_meta:
        distribution = ' '.join(t for t in info_meta['distribution'] if t)
        current_distribution = platform.linux_distribution()[0:2]
        current_distribution = ' '.join(t for t in current_distribution if t)
        print("Distribution: %s (current: %s)" % (
              distribution, current_distribution or "(not Linux)"))
    if 'runs' in info:
        runs = info['runs']
        print("Runs (%d):" % len(runs))
        for run in runs:
            cmdline = ' '.join(shell_escape(a) for a in run['argv'])
            if len(runs) == 1 and run['id'] == "run0":
                print("    %s" % cmdline)
            else:
                print("    %s: %s" % (run['id'], cmdline))
            if verbosity >= 2:
                print("        wd: %s" % run['workingdir'])
                if 'signal' in run:
                    print("        signal: %d" % run['signal'])
                else:
                    print("        exitcode: %d" % run['exitcode'])
                if run.get('walltime') is not None:
                    print("        walltime: %s" % run['walltime'])

    inputs_outputs = info.get('inputs_outputs')
    if inputs_outputs:
        if verbosity < 2:
            print("Inputs/outputs files (%d): %s" % (
                  len(inputs_outputs), ", ".join(sorted(inputs_outputs))))
        else:
            print("Inputs/outputs files (%d):" % len(inputs_outputs))
            for name, f in sorted(iteritems(inputs_outputs)):
                t = []
                if f['read_runs']:
                    t.append("in")
                if f['write_runs']:
                    t.append("out")
                print("    %s (%s): %s" % (name, ' '.join(t), f['path']))

    unpacker_status = info.get('unpacker_status')
    if unpacker_status:
        print("\n----- Unpackers -----")
        for s, n in [(COMPAT_OK, "Compatible"), (COMPAT_MAYBE, "Unknown"),
                     (COMPAT_NO, "Incompatible")]:
            if s != COMPAT_OK and verbosity < 2:
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


def print_info(args):
    """Writes out some information about a pack file.
    """
    pack = Path(args.pack[0])

    info = get_package_info(pack, read_data=args.json or args.verbosity >= 2)
    if args.json:
        json.dump(info, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        _print_package_info(pack, info, args.verbosity)


def showfiles(args):
    """Writes out the input and output files.

    Works both for a pack file and for an extracted directory.
    """
    def parse_run(runs, s):
        for i, run in enumerate(runs):
            if run['id'] == s:
                return i
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

    show_inputs = args.input or not args.output
    show_outputs = args.output or not args.input

    def file_filter(fio):
        if file_filter.run is None:
            return ((show_inputs and fio.read_runs) or
                    (show_outputs and fio.write_runs))
        else:
            return ((show_inputs and file_filter.run in fio.read_runs) or
                    (show_outputs and file_filter.run in fio.write_runs))

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

        if show_inputs:
            shown = False
            for input_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.read_runs and file_filter(f):
                    if not shown:
                        print("Input files:")
                        shown = True
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
            if not shown:
                print("Input files: none")

        if show_outputs:
            shown = False
            for output_name, f in sorted(iteritems(config.inputs_outputs)):
                if f.write_runs and file_filter(f):
                    if not shown:
                        print("Output files:")
                        shown = True
                    if args.verbosity >= 2:
                        print("    %s (%s)" % (output_name, f.path))
                    else:
                        print("    %s" % output_name)
            if not shown:
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
    parser.add_argument('--json', action='store_true', default=False)
    parser.set_defaults(func=print_info)


def setup_showfiles(parser, **kwargs):
    """Prints out input and output file names
    """
    parser.add_argument('pack', nargs=1,
                        help="Pack or directory to read from")
    parser.add_argument('run', nargs=argparse.OPTIONAL,
                        help="Run whose input and output files will be listed")
    parser.add_argument('--input', action='store_true',
                        help="Only show input files")
    parser.add_argument('--output', action='store_true',
                        help="Only show output files")
    parser.set_defaults(func=showfiles)
