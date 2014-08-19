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
import sys

from reprounzip.pack_info import print_info


__version__ = '0.3'


unpackers = {}


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
    parser_info.set_defaults(func=lambda args: print_info(args, unpackers))

    # Loads commands from plugins
    for entry_point in iter_entry_points('reprounzip.unpackers'):
        setup_function = entry_point.load()
        name = entry_point.name
        # Docstring is used as description (used for detailed help)
        descr = setup_function.__doc__.strip()
        # First line of docstring is the help (used for general help)
        descr_1 = descr.split('\n', 1)[0]
        plugin_parser = subparsers.add_parser(
                name, parents=[options],
                help=descr_1, description=descr,
                formatter_class=argparse.RawDescriptionHelpFormatter)
        info = setup_function(plugin_parser)
        if info is None:
            info = {}
        unpackers[name] = info

    args = parser.parse_args()
    levels = [logging.CRITICAL, logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 3)])
    args.func(args)
    sys.exit(0)


if __name__ == '__main__':
    main()
