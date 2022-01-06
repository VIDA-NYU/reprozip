# Copyright (C) 2022 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import argparse
import sys

from reprozip_core.common import setup_logging
from . import __version__


def cmd_capture(args):
    """Reproduce the application and run the capture.
    """
    pass


def cmd_replay():
    """Reproduce the application and replay the captured archive.
    """
    pass


def main():
    def add_options(opts):
        opts.add_argument(
            '-v', '--verbose', action='count', default=0,
            dest='verbosity', help="augments verbosity level",
        )
        opts.add_argument(
            '--version', action='version',
            version="reprozip-web version %s" % __version__,
        )

    parser = argparse.ArgumentParser(
        description="Capture and Replay Remote Web Content for ReproZip",
        epilog="Please report issues to reprozip@nyu.edu",
    )
    add_options(parser)
    subparser = parser.add_subparsers(
        title="subcommands", metavar='', dest='cmd',
    )

    parser_capture = subparser.add_parser(
        'capture',
        help="Runs an RPZ and crawl it, recording static content",
    )
    add_options(parser_capture)
    parser_capture.set_defaults(func=cmd_capture)

    parser_replay = subparser.add_parser(
        'replay',
        help="Runs an RPZ, additionally serving recorded static content",
    )
    add_options(parser_replay)
    parser_replay.set_defaults(func=cmd_replay)

    args = parser.parse_args()
    setup_logging('REPROUNZIP-WEB', args.verbosity)
    if getattr(args, 'func', None) is None:
        parser.print_help(sys.stderr)
        sys.exit(2)
    args.func(args)
