# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Entry point for the reprounzip utility.

This contains :func:`~reprounzip.reprounzip.main`, which is the entry point
declared to setuptools. It is also callable directly.

It dispatchs to plugins registered through pkg_resources as entry point
``reprounzip.unpackers``.
"""

from __future__ import absolute_import, unicode_literals

import argparse
import codecs
import locale
import logging
from pkg_resources import iter_entry_points
import platform
from rpaths import Path
import sys
import tarfile

from reprounzip.unpackers.common import load_config, COMPAT_OK, COMPAT_MAYBE, \
    COMPAT_NO
from reprounzip.utils import hsize


__version__ = '0.3'


unpackers = []


def print_info(args):
    """Writes out some information about a pack file.
    """
    pack = Path(args.pack[0])

    # Loads config
    runs, packages, other_files = config = load_config(pack)

    pack_total_size = 0
    pack_total_paths = 0
    pack_files = 0
    pack_dirs = 0
    pack_symlinks = 0
    pack_others = 0
    tar = tarfile.open(str(pack), 'r:*')
    for m in tar.getmembers():
        if not m.name.startswith('DATA/'):
            continue
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
    tar.close()

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

    current_architecture = platform.machine()
    current_distribution = platform.linux_distribution()[0:2]

    print("Pack file: %s" % pack)
    print("----- Pack information -----")
    print("Compressed size: %s" % hsize(pack.size()))
    print("Unpacked size: %s" % hsize(pack_total_size))
    print("Total packed paths: %d" % pack_total_paths)
    print("    Files: %d" % pack_files)
    print("    Directories: %d" % pack_dirs)
    print("    Symbolic links: %d" % pack_symlinks)
    if pack_others:
        print("    Unknown (what!?): %d" % pack_others)
    print("----- Metadata -----")
    print("Total paths: %d" % meta_total_paths)
    print("Listed packed paths: %d" % meta_packed_paths)
    if packages:
        print("Total packages: %d" % meta_packages)
        print("Packed packages: %d" % meta_packed_packages)
        print("    Files from packed packages: %d" %
              meta_packed_packages_files)
        print("    Files from unpacked packages: %d" %
              meta_unpacked_packages_files)
    if runs:
        print("Architecture: %s (current: %s)" % (meta_architecture,
                                                  current_architecture))
        print("Distribution: %s (current: %s)" % (meta_distribution,
                                                  current_distribution))
        print("Executions (%d):" % len(runs))
        for r in runs:
            print("    %s" % ' '.join(r['argv']))
            print("        wd: %s" % r['workingdir'])
            if 'signal' in r:
                print("        signal: %d" % r['signal'])
            else:
                print("        exitcode: %d" % r['exitcode'])

    # Unpacker compatibility
    print("----- Unpackers -----")
    unpacker_status = {}
    for upk in unpackers:
        if 'test_compatibility' in upk:
            res, msg = upk['test_compatibility'](pack, config=config)
            unpacker_status.setdefault(res, []).append((upk['name'], msg))
        else:
            unpacker_status.setdefault(None, []).append((upk['name'], None))
    for s, n in [(COMPAT_OK, "Compatible"), (COMPAT_MAYBE, "Unknown"),
                 (COMPAT_NO, "Incompatible")]:
        if s not in unpacker_status:
            continue
        upks = unpacker_status[s]
        print("%s (%d):" % (n, len(upks)))
        for upk_name, msg in upks:
            if msg is not None:
                print("    %s (%s)" % (upk_name, msg))
            else:
                print("    %s" % upk_name)


def main():
    """Entry point when called on the command line.
    """
    global unpackers

    # Locale
    locale.setlocale(locale.LC_ALL, '')

    # Encoding for output streams
    if str == bytes:
        writer = codecs.getwriter(locale.getpreferredencoding())
        sys.stdout = writer(sys.stdout)
        sys.stderr = writer(sys.stderr)

    # Parses command-line

    # General options
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('-v', '--verbose', action='count', default=1,
                         dest='verbosity',
                         help="augments verbosity level")

    parser = argparse.ArgumentParser(
            description="Reproducible experiments tool.",
            epilog="Please report issues to reprozip-users@vgc.poly.edu",
            parents=[options])
    subparsers = parser.add_subparsers(title="formats", metavar='')

    parser_info = subparsers.add_parser(
            'info', parents=[options],
            help="Prints out some information about a pack")
    parser_info.add_argument('pack', nargs=1,
                             help="Pack to read")
    parser_info.set_defaults(func=print_info)

    # Loads commands from plugins
    for entry_point in iter_entry_points('reprounzip.unpackers'):
        setup_function = entry_point.load()
        info = setup_function(subparsers=subparsers, general_options=options)
        if info is None:
            info = [{}]
        for upk in info:
            upk['project'] = entry_point.dist.project_name
            upk['ep_name'] = '%s/%s' % (entry_point.dist.project_name,
                                        entry_point.name)
            if 'name' not in upk:
                upk['name'] = upk['ep_name']
        unpackers += info

    args = parser.parse_args()
    levels = [logging.CRITICAL, logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 3)])
    args.func(args)
    sys.exit(0)


if __name__ == '__main__':
    main()
