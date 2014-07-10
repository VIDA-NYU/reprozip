# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import argparse
import codecs
import locale
import logging
from pkg_resources import iter_entry_points
import sys


__version__ = '0.2'


def main():
    """Entry point when called on the command line.
    """
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

    # Loads commands from plugins
    for entry_point in iter_entry_points('reprounzip.unpackers'):
        setup_function = entry_point.load()
        setup_function(subparsers=subparsers, general_options=options)

    args = parser.parse_args()
    levels = [logging.CRITICAL, logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 3)])
    args.func(args)
    sys.exit(0)
