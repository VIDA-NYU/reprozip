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

if __name__ == '__main__':  # noqa
    from reprounzip.main import main
    main()

import argparse
import locale
import logging
from pkg_resources import iter_entry_points
import sys
import traceback

from reprounzip.common import setup_logging, \
    setup_usage_report, enable_usage_report, \
    submit_usage_report, record_usage
from reprounzip import signals
from reprounzip.unpackers.common import UsageError


__version__ = '1.1.0'


unpackers = {}


def get_plugins(entry_point_name):
    for entry_point in iter_entry_points(entry_point_name):
        try:
            func = entry_point.load()
        except Exception:
            print("Plugin %s from %s %s failed to initialize!" % (
                  entry_point.name,
                  entry_point.dist.project_name, entry_point.dist.version),
                  file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            continue
        name = entry_point.name
        # Docstring is used as description (used for detailed help)
        descr = func.__doc__.strip()
        # First line of docstring is the help (used for general help)
        descr_1 = descr.split('\n', 1)[0]

        yield name, func, descr, descr_1


class RPUZArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help(sys.stderr)
        sys.exit(2)


def usage_report(args):
    if bool(args.enable) == bool(args.disable):
        logging.critical("What do you want to do?")
        raise UsageError
    enable_usage_report(args.enable)
    sys.exit(0)


def main():
    """Entry point when called on the command-line.
    """
    # Locale
    locale.setlocale(locale.LC_ALL, '')

    # Parses command-line

    # General options
    def add_options(opts):
        opts.add_argument('--version', action='version',
                          version="reprounzip version %s" % __version__)

    # Loads plugins
    for name, func, descr, descr_1 in get_plugins('reprounzip.plugins'):
        func()

    parser = RPUZArgumentParser(
        description="reprounzip is the ReproZip component responsible for "
                    "unpacking and reproducing an experiment previously "
                    "packed with reprozip",
        epilog="Please report issues to reprozip-users@vgc.poly.edu")
    add_options(parser)
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        dest='verbosity',
                        help="augments verbosity level")
    subparsers = parser.add_subparsers(title="subcommands", metavar='')

    # usage_report subcommand
    parser_stats = subparsers.add_parser(
        'usage_report',
        help="Enables or disables anonymous usage reports")
    add_options(parser_stats)
    parser_stats.add_argument('--enable', action='store_true')
    parser_stats.add_argument('--disable', action='store_true')
    parser_stats.set_defaults(func=usage_report)

    # Loads unpackers
    for name, func, descr, descr_1 in get_plugins('reprounzip.unpackers'):
        plugin_parser = subparsers.add_parser(
            name, help=descr_1, description=descr,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        add_options(plugin_parser)
        info = func(plugin_parser)
        plugin_parser.set_defaults(selected_unpacker=name)
        if info is None:
            info = {}
        unpackers[name] = info

    signals.pre_parse_args(parser=parser, subparsers=subparsers)
    args = parser.parse_args()
    signals.post_parse_args(args=args)
    if getattr(args, 'func', None) is None:
        parser.print_help(sys.stderr)
        sys.exit(2)
    signals.unpacker = getattr(args, 'selected_unpacker', None)
    setup_logging('REPROUNZIP', args.verbosity)

    setup_usage_report('reprounzip', __version__)
    if hasattr(args, 'selected_unpacker'):
        record_usage(unpacker=args.selected_unpacker)
    signals.pre_setup.subscribe(lambda **kw: record_usage(setup=True))
    signals.pre_run.subscribe(lambda **kw: record_usage(run=True))

    try:
        try:
            args.func(args)
        except UsageError:
            raise
        except Exception as e:
            signals.application_finishing(reason=e)
            submit_usage_report(result=type(e).__name__)
            raise
        else:
            signals.application_finishing(reason=None)
    except UsageError:
        parser.print_help(sys.stderr)
        sys.exit(2)
    submit_usage_report(result='success')
    sys.exit(0)
