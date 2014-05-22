from __future__ import unicode_literals

import argparse
import codecs
import locale
import logging
import os
import sqlite3
import sys
import tempfile

import reprozip.graph
import reprozip.pack
import reprozip.tracer.trace
from reprozip import _pytracer


def print_db(database):
    """Prints out database content.
    """
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    processes = cur.execute(
            '''
            SELECT id, parent, timestamp
            FROM processes;
            ''')
    print("\nProcesses:")
    header = "+------+--------+--------------------+"
    print(header)
    print("|  id  | parent |      timestamp     |")
    print(header)
    for r_id, r_parent, r_timestamp in processes:
        f_id = "{: 5d} ".format(r_id)
        if r_parent is not None:
            f_parent = "{: 7d} ".format(r_parent)
        else:
            f_parent = "        "
        f_timestamp = "{: 19d} ".format(r_timestamp)
        print('|'.join(('', f_id, f_parent, f_timestamp, '')))
        print(header)
    cur.close()

    cur = conn.cursor()
    processes = cur.execute(
            '''
            SELECT id, name, timestamp, process, argv
            FROM executed_files;
            ''')
    print("\nExecuted files:")
    header = ("+--------+--------------------+---------+------+---------------"
              "---------------+")
    print(header)
    print("|   id   |      timestamp     | process | name and argv            "
          "    |")
    print(header)
    for r_id, r_name, r_timestamp, r_process, r_argv in processes:
        f_id = "{: 7d} ".format(r_id)
        f_timestamp = "{: 19d} ".format(r_timestamp)
        f_proc = "{: 8d} ".format(r_process)
        argv = r_argv.split('\0')
        cmdline = ' '.join(repr(a) for a in argv)
        if argv[0] != os.path.basename(r_name):
            cmdline = "(%s) %s" % (r_name, cmdline)
        f_cmdline = " {: <28s} ".format(cmdline)
        print('|'.join(('', f_id, f_timestamp, f_proc, f_cmdline, '')))
        print(header)
    cur.close()

    cur = conn.cursor()
    processes = cur.execute(
            '''
            SELECT id, name, timestamp, mode, process
            FROM opened_files;
            ''')
    print("\nFiles:")
    header = ("+--------+--------------------+---------+------+---------------"
              "---------------+")
    print(header)
    print("|   id   |      timestamp     | process | mode | name              "
          "           |")
    print(header)
    for r_id, r_name, r_timestamp, r_mode, r_process in processes:
        f_id = "{: 7d} ".format(r_id)
        f_timestamp = "{: 19d} ".format(r_timestamp)
        f_proc = "{: 8d} ".format(r_process)
        f_mode = "{: 5d} ".format(r_mode)
        f_name = " {: <28s} ".format(r_name)
        print('|'.join(('', f_id, f_timestamp, f_proc, f_mode, f_name, '')))
        print(header)
    cur.close()

    conn.close()


def testrun(args):
    """testrun subcommand.

    Runs the command with the tracer using a temporary sqlite3 database, then
    reads it and dumps it out.

    Not really useful, except for debugging.
    """
    fd, database = tempfile.mkstemp(prefix='reprozip_', suffix='.sqlite3')
    os.close(fd)
    try:
        if args.arg0 is not None:
            argv = [args.arg0] + args.cmdline[1:]
        else:
            argv = args.cmdline
        c = _pytracer.execute(args.cmdline[0], argv, database)
        print("\n\n-----------------------------------------------------------"
              "--------------------")
        print_db(database)
        if c != 0:
            if c & 0x0100:
                print("\nWarning: program appears to have been terminated by "
                      "signal %d" % (c & 0xFF))
            else:
                print("\nWarning: program exited with non-zero code %d" % c)
    finally:
        os.remove(database)


def trace(args):
    """trace subcommand.

    Simply calls reprozip.tracer.trace() with the arguments from argparse.
    """
    if args.arg0 is not None:
        argv = [args.arg0] + args.cmdline[1:]
    else:
        argv = args.cmdline
    reprozip.tracer.trace.trace(args.cmdline[0], argv, args.dir, args.append)


def graph(args):
    """graph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in GraphViz DOT
    format.
    """
    reprozip.graph.generate(args.target[0], args.dir, args.all_forks)


def pack(args):
    """pack subcommand.

    Reads in the configuration file and writes out a tarball.
    """
    reprozip.pack.pack(args.target, args.dir)


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
    options.add_argument('-d', '--dir', default='.reprozip',
                         help="where to store database and configuration file "
                         "(default: ./.reprozip)")

    parser = argparse.ArgumentParser(
            description="Reproducible experiments tool.",
            epilog="Please report issues to reprozip-users@vgc.poly.edu",
            parents=[options])
    subparsers = parser.add_subparsers(title="commands", metavar='')

    # trace command
    parser_trace = subparsers.add_parser(
            'trace', parents=[options],
            help="Runs the program and writes out database and configuration "
            "file")
    parser_trace.add_argument(
            '-a',
            dest='arg0',
            help="argument 0 to program, if different from program path")
    parser_trace.add_argument(
            '-c', '--continue', action='store_true', dest='append',
            help="add to the previous run instead of replacing it")
    parser_trace.add_argument('cmdline', nargs=argparse.REMAINDER,
                              help="command-line to run under trace")
    parser_trace.set_defaults(func=trace)

    # testrun command
    parser_testrun = subparsers.add_parser(
            'testrun', parents=[options],
            help="Runs the program and writes out the database contents")
    parser_testrun.add_argument(
            '-a',
            dest='arg0',
            help="argument 0 to program, if different from program path")
    parser_testrun.add_argument('cmdline', nargs=argparse.REMAINDER)
    parser_testrun.set_defaults(func=testrun)

    # graph command
    parser_graph = subparsers.add_parser(
            'graph', parents=[options],
            help="Generates a provenance graph from the trace data")
    parser_graph.add_argument('target', nargs=1,
                              help="Destination DOT file")
    parser_graph.add_argument('-F', '--all-forks', action='store_true',
                              help="Show forked processes before they exec")
    parser_graph.set_defaults(func=graph)

    # pack command
    parser_pack = subparsers.add_parser(
            'pack', parents=[options],
            help="Packs the experiment according to the current configuration")
    parser_pack.add_argument('target', nargs='?', default='experiment.rpz',
                             help="Destination file")
    parser_pack.set_defaults(func=pack)

    args = parser.parse_args()
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 2)])
    if 'cmdline' in args and not args.cmdline:
        parser.error("missing command-line")
    args.func(args)
    sys.exit(0)
