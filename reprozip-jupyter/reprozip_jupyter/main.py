# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import argparse
import sys

from . import __version__
from . import run
from . import trace


def main():
    def add_options(opts):
        opts.add_argument('-v', '--verbose', action='count', default=0,
                          dest='verbosity', help="augments verbosity level")
        opts.add_argument('--version', action='version',
                          version="reprounzip-jupyter version %s" %
                                  __version__)

    parser = argparse.ArgumentParser(
        description="Jupyter Notebook tracing/reproduction for ReproZip",
        epilog="Please report issues to reprozip-users@vgc.poly.edu")
    add_options(parser)
    subparser = parser.add_subparsers(title="subcommands", metavar='',
                                      dest='cmd')

    parser_trace = subparser.add_parser(
        'trace',
        help="Runs a Jupyter notebook under ReproZip trace to generate the "
             "accompanying environment package")
    add_options(parser_trace)
    trace.setup(parser_trace)

    parser_run = subparser.add_parser(
        'run',
        help="Runs a Jupyter notebook server that will spawn notebooks in "
             "Docker containers running in the given unpacked environment")
    add_options(parser_run)
    run.setup(parser_run)

    args = parser.parse_args()
    if getattr(args, 'func', None) is None:
        parser.print_help(sys.stderr)
        sys.exit(2)
    args.func(args)
