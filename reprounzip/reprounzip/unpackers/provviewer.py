# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Prov Viewer exporter.

This exports the trace data into a format suitable for the Prov Viewer tool
(https://github.com/gems-uff/prov-viewer).

See schema: https://git.io/provviewer-xsd
"""

from __future__ import division, print_function, unicode_literals

import argparse
import logging
from rpaths import Path
import sqlite3
import sys

from reprounzip.common import RPZPack, load_config
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_NO
from reprounzip.utils import stderr


def generate(target, configfile, database):
    """Go over the trace and generate the graph file.
    """
    # Reads package ownership from the configuration
    if not configfile.is_file():
        logging.critical("Configuration file does not exist!\n"
                         "Did you forget to run 'reprozip trace'?\n"
                         "If not, you might want to use --dir to specify an "
                         "alternate location.")
        sys.exit(1)

    config = load_config(configfile, canonical=False)

    TODO


def provgraph(args):
    """provgraph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in Provenance
    Viewer graph format."""
    def call_generate(args, config, trace):
        generate(Path(args.target[0]), config, trace)

    if args.pack is not None:
        rpz_pack = RPZPack(args.pack)
        with rpz_pack.with_config() as config:
            with rpz_pack.with_trace() as trace:
                call_generate(args, config, trace)
    else:
        call_generate(args,
                      Path(args.dir) / 'config.yml',
                      Path(args.dir) / 'trace.sqlite3')


def disabled_bug13676(args):
    stderr.write("Error: your version of Python, %s, is not supported\n"
                 "Versions before 2.7.3 are affected by bug 13676 and will "
                 "not be able to read\nthe trace "
                 "database\n" % sys.version.split(' ', 1)[0])
    sys.exit(1)


def setup(parser, **kwargs):
    """Generates a Prov Viewer graph from the trace data
    """

    # http://bugs.python.org/issue13676
    # This prevents repro(un)zip from reading argv and envp arrays from trace
    if sys.version_info < (2, 7, 3):
        parser.add_argument('rest_of_cmdline', nargs=argparse.REMAINDER,
                            help=argparse.SUPPRESS)
        parser.set_defaults(func=disabled_bug13676)
        return {'test_compatibility': (COMPAT_NO, "Python >2.7.3 required")}

    parser.add_argument('target', nargs=1, help="Destination DOT file")
    parser.add_argument(
        '-d', '--dir', default='.reprozip-trace',
        help="where the database and configuration file are stored (default: "
        "./.reprozip-trace)")
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to extract (defaults to reading from --dir)")
    parser.set_defaults(func=provgraph)

    return {'test_compatibility': COMPAT_OK}
