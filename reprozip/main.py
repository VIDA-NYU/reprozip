from __future__ import unicode_literals

import argparse
import codecs
import locale
import logging
import os
import sqlite3
import sys
import tempfile

import reprozip.tracer
from reprozip import _pytracer


def print_db(database):
    """Prints out database content.
    """
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    processes = cur.execute('''
            SELECT id, parent, timestamp
            FROM processes;
            ''')
    print("\nProcesses:")
    header = "+------+--------+--------------------+"
    print(header)
    print("|  id  | parent |      timestamp     |")
    print(header)
    for proc in processes:
        f_id = "{: 5d} ".format(proc['id'])
        if proc['parent'] is not None:
            f_parent = "{: 7d} ".format(proc['parent'])
        else:
            f_parent = "        "
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        print('|'.join(('', f_id, f_parent, f_timestamp, '')))
        print(header)
    cur.close()

    cur = conn.cursor()
    processes = cur.execute('''
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
    for proc in processes:
        f_id = "{: 7d} ".format(proc['id'])
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        f_proc = "{: 8d} ".format(proc['process'])
        f_mode = "{: 5d} ".format(proc['mode'])
        f_name = " {: <29s}".format(proc['name'])
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
        print(args.cmdline[0], argv, database)
        _pytracer.execute(args.cmdline[0], argv, database)
        print("\n\n-----------------------------------------------------------"
              "--------------------")
        print_db(database)
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
    reprozip.tracer.trace(args.cmdline[0], argv, args.dir, args.append)


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
    parser = argparse.ArgumentParser(
            description="Reproducible experiments tool.",
            epilog="Please report issues to remi.rampin@nyu.edu")
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        dest='verbosity',
                        help="augments verbosity level")
    parser.add_argument('-d', '--dir', default='.reprozip',
                        help="where to store database and configuration file "
                        "(default: ./.reprozip)")
    subparsers = parser.add_subparsers(title="commands", metavar='')

    # trace command
    parser_trace = subparsers.add_parser(
            'trace',
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
            'testrun',
            help="Runs the program and writes out the database contents")
    parser_testrun.add_argument(
            '-a',
            dest='arg0',
            help="argument 0 to program, if different from program path")
    parser_testrun.add_argument('cmdline', nargs=argparse.REMAINDER)
    parser_testrun.set_defaults(func=testrun)

    args = parser.parse_args()
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(level=levels[min(args.verbosity, 2)])
    if 'cmdline' in args and not args.cmdline:
        parser.error("missing command-line")
    args.func(args)
    sys.exit(0)
