from __future__ import unicode_literals

import argparse
import codecs
import locale
import logging
import os
import shutil
import sys
import tarfile
import tempfile

import reprounzip.graph
from reprounzip.unpack import installpkgs, create_chroot, create_vagrant


def graph(args):
    """graph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in GraphViz DOT
    format.
    """
    if args.pack is not None:
        tmp = tempfile.mkdtemp(prefix='reprozip_')
        try:
            tar = tarfile.open(args.pack, 'r:*')
            f = tar.extractfile('METADATA/version')
            version = f.read()
            f.close()
            if version != b'REPROZIP VERSION 1\n':
                sys.stderr.write("Unknown pack format\n")
                sys.exit(1)
            try:
                tar.extract('METADATA/config.yml', path=tmp)
                tar.extract('METADATA/trace.sqlite3', path=tmp)
            except KeyError as e:
                sys.stderr.write("Error extracting from pack: %s" % e.args[0])
            reprounzip.graph.generate(args.target[0],
                                      os.path.join(tmp, 'METADATA'),
                                      args.all_forks)
        finally:
            shutil.rmtree(tmp)
    else:
        reprounzip.graph.generate(args.target[0], args.dir, args.all_forks)


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
    options.add_argument('-v', '--verbose', action='count', default=0,
                         dest='verbosity',
                         help="augments verbosity level")

    # General options
    parser = argparse.ArgumentParser(
            description="Reproducible experiments tool.",
            epilog="Please report issues to reprozip-users@vgc.poly.edu",
            parents=[options])
    subparsers = parser.add_subparsers(title="formats", metavar='')

    # graph command
    parser_graph = subparsers.add_parser(
            'graph', parents=[options],
            help="Generates a provenance graph from the trace data")
    parser_graph.add_argument('target', nargs=1,
                              help="Destination DOT file")
    parser_graph.add_argument('-F', '--all-forks', action='store_true',
                              help="Show forked processes before they exec")
    parser_graph.add_argument(
            '-d', '--dir', default='.reprozip',
            help="where the database and configuration file are stored "
            "(default: ./.reprozip)")
    parser_graph.add_argument(
            'pack', nargs=argparse.OPTIONAL,
            help="Pack to extract (defaults to reading from --dir)")
    parser_graph.set_defaults(func=graph)

    # Install the required packages
    parser_installpkgs = subparsers.add_parser(
            'installpkgs', parents=[options],
            help="Installs the required packages on this system")
    parser_installpkgs.add_argument('pack', nargs=1,
                                    help="Pack to process")
    parser_installpkgs.add_argument(
            '-y', '--assume-yes',
            help="Assumes yes for package manager's questions (if supported)")
    parser_installpkgs.set_defaults(func=installpkgs)

    # Unpacks all the file so the experiment can be run with chroot
    parser_chroot = subparsers.add_parser(
            'chroot', parents=[options],
            help="Unpacks the files so the experiment can be run with chroot")
    parser_chroot.add_argument('pack', nargs=1,
                               help="Pack to extract")
    parser_chroot.add_argument('target', nargs=1,
                               help="Directory to create")
    parser_chroot.set_defaults(func=create_chroot)

    # Creates a virtual machine with Vagrant
    parser_vagrant = subparsers.add_parser(
            'vagrant', parents=[options],
            help="Unpacks the files and sets up the experiment to be run in "
            "Vagrant")
    parser_vagrant.add_argument('pack', nargs=1,
                                help="Pack to extract")
    parser_vagrant.add_argument('target', nargs=1,
                                help="Directory to create")
    parser_vagrant.add_argument(
            '--use-chroot',
            help="Use a chroot and the original files in the virtual machine")
    parser_vagrant.set_defaults(func=create_vagrant)

    args = parser.parse_args()
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 2)])
    args.func(args)
    sys.exit(0)
