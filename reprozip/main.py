import argparse
import codecs
import locale
import os
import sqlite3
import sys
import tempfile

import reprozip.tracer
from reprozip import _pytracer


def print_db(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    processes = cur.execute('''
            SELECT id, parent, timestamp
            FROM processes;
            ''')
    print(u"\nProcesses:")
    header = u"+------+--------+--------------------+"
    print(header)
    print(u"|  id  | parent |      timestamp     |")
    print(header)
    for proc in processes:
        f_id = "{: 5d} ".format(proc['id'])
        if proc['parent'] is not None:
            f_parent = "{: 7d} ".format(proc['parent'])
        else:
            f_parent = "        "
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        print(u'|'.join(('', f_id, f_parent, f_timestamp, '')))
        print(header)
    cur.close()

    cur = conn.cursor()
    processes = cur.execute('''
            SELECT id, name, timestamp, mode, process
            FROM opened_files;
            ''')
    print(u"\nFiles:")
    header = (u"+--------+--------------------+---------+------+--------------"
              u"----------------+")
    print(header)
    print(u"|   id   |      timestamp     | process | mode | name          "
          u"               |")
    print(header)
    for proc in processes:
        f_id = "{: 7d} ".format(proc['id'])
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        f_proc = "{: 8d} ".format(proc['process'])
        f_mode = "{: 5d} ".format(proc['mode'])
        f_name = " {: <29s}".format(proc['name'])
        print(u'|'.join(('', f_id, f_timestamp, f_proc, f_mode, f_name, '')))
        print(header)
    cur.close()

    conn.close()


def testrun(args):
    fd, database = tempfile.mkstemp(prefix='reprozip_', suffix='.sqlite3')
    os.close(fd)
    try:
        if args.arg0 is not None:
            argv = [args.arg0] + args.cmdline[1:]
        else:
            argv = args.cmdline
        print(args.cmdline[0], argv, database)
        _pytracer.execute(args.cmdline[0], argv, database)
        print(u"\n\n----------------------------------------------------------"
              u"---------------------")
        print_db(database)
    finally:
        os.remove(database)


def trace(args):
    if args.arg0 is not None:
        argv = [args.arg0] + args.cmdline[1:]
    else:
        argv = args.cmdline
    reprozip.tracer.trace(args.cmdline[0], argv)


def main():
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
            description=u"Reproducible experiments tool.",
            epilog=u"Please report issues to remi.rampin@nyu.edu")
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help=u"augments verbosity level")
    parser.add_argument('-d', '--dir',
                        help=u"where to store database and configuration file "
                        u"(default: ./.reprozip)")
    subparsers = parser.add_subparsers(title="commands", metavar='')

    # trace command
    parser_trace = subparsers.add_parser(
            'trace',
            help=u"Runs the program and writes out database and configuration "
            u"file")
    parser_trace.add_argument(
            '-a',
            dest='arg0',
            help=u"argument 0 to program, if different from program path")
    parser_trace.add_argument('cmdline', nargs=argparse.REMAINDER)
    parser_trace.set_defaults(func=trace)

    # testrun command
    parser_testrun = subparsers.add_parser(
            'testrun',
            help=u"Runs the program and writes out the database contents")
    parser_testrun.add_argument(
            '-a',
            dest='arg0',
            help=u"argument 0 to program, if different from program path")
    parser_testrun.add_argument('cmdline', nargs=argparse.REMAINDER)
    parser_testrun.set_defaults(func=testrun)

    args = parser.parse_args()
    args.func(args)
    sys.exit(0)
