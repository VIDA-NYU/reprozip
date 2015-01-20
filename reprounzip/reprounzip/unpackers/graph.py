# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Graph plugin for reprounzip.

This is not actually an unpacker, it just creates a graph from the metadata
collected by the reprozip tracer (either from a pack file or the initial .rpz
directory).

It creates a file in GraphViz DOT format, which can be turned into an image by
using the dot utility.

See http://www.graphviz.org/
"""

from __future__ import unicode_literals

import argparse
import heapq
import logging
from rpaths import PosixPath, Path
import sqlite3
import sys
import tarfile

from reprounzip.common import FILE_READ, FILE_WRITE, FILE_WDIR, load_config
from reprounzip.orderedset import OrderedSet
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_NO
from reprounzip.utils import PY3, unicode_, iteritems, escape, \
    CommonEqualityMixin


C_INITIAL = 0   # First process or don't know
C_FORK = 1      # Might actually be any one of fork, vfork or clone
C_EXEC = 2      # Replaced image with execve
C_FORKEXEC = 3  # A fork then an exec, folded as one because all_forks==False


class Process(CommonEqualityMixin):
    """Structure representing a process in the experiment.
    """
    def __init__(self, pid, parent, timestamp, acted, binary, created):
        self.pid = pid
        self.parent = parent
        self.timestamp = timestamp
        # Whether that process has done something yet. If it execve()s and
        # hasn't done anything since it forked, no need for it to appear
        self.acted = acted
        # Executable file
        self.binary = binary
        # How was this process created, one of the C_* constants
        self.created = created

    def __hash__(self):
        return id(self)


def generate(target, directory, all_forks=False):
    """Main function for the graph subcommand.
    """
    # In here, a file is any file on the filesystem. A binary is a file, that
    # gets executed. A process is a system-level task, identified by its pid
    # (pids don't get reused in the database).
    # What I call program is the couple (process, binary), so forking creates a
    # new program (with the same binary) and exec'ing creates a new program as
    # well (with the same process)
    # Because of this, fork+exec will create an intermediate program that
    # doesn't do anything (new process but still old binary). If that program
    # doesn't do anything worth showing on the graph, it will be erased, unless
    # all_forks is True (--all-forks).

    database = directory / 'trace.sqlite3'

    # Reads package ownership from the configuration
    configfile = directory / 'config.yml'
    if not configfile.is_file():
        logging.critical("Configuration file does not exist!\n"
                         "Did you forget to run 'reprozip trace'?\n"
                         "If not, you might want to use --dir to specify an "
                         "alternate location.")
        sys.exit(1)
    runs, packages, other_files, patterns = load_config(configfile,
                                                        canonical=False)
    packages = dict((f.path, pkg) for pkg in packages for f in pkg.files)

    if PY3:
        # On PY3, connect() only accepts unicode
        conn = sqlite3.connect(str(database))
    else:
        conn = sqlite3.connect(database.path)

    # This is a bit weird. We need to iterate on all types of events at the
    # same time, ordering by timestamp, so we decorate-sort-undecorate
    # Decoration adds timestamp (for sorting) and tags by event type, one of
    # 'process', 'open' or 'exec'

    # Reads processes from the database
    process_cursor = conn.cursor()
    process_rows = process_cursor.execute(
            '''
            SELECT id, parent, timestamp
            FROM processes
            ORDER BY id
            ''')
    processes = {}
    all_programs = []

    # ... and opened files...
    file_cursor = conn.cursor()
    file_rows = file_cursor.execute(
            '''
            SELECT name, timestamp, mode, process
            FROM opened_files
            ORDER BY id
            ''')
    binaries = set()
    files = OrderedSet()
    edges = OrderedSet()

    # ... as well as executed files.
    exec_cursor = conn.cursor()
    exec_rows = exec_cursor.execute(
            '''
            SELECT name, timestamp, process, argv
            FROM executed_files
            ORDER BY id
            ''')

    # Loop on all event lists
    logging.info("Getting all events from database...")
    rows = heapq.merge(((r[2], 'process', r) for r in process_rows),
                       ((r[1], 'open', r) for r in file_rows),
                       ((r[1], 'exec', r) for r in exec_rows))
    for ts, event_type, data in rows:
        if event_type == 'process':
            r_id, r_parent, r_timestamp = data
            if r_parent is not None:
                parent = processes[r_parent]
                binary = parent.binary
            else:
                parent = None
                binary = None
            p = Process(r_id,
                        parent,
                        r_timestamp,
                        False,
                        binary,
                        C_INITIAL if r_parent is None else C_FORK)
            processes[r_id] = p
            all_programs.append(p)

        elif event_type == 'open':
            r_name, r_timestamp, r_mode, r_process = data
            r_name = PosixPath(r_name)
            if r_mode != FILE_WDIR:
                process = processes[r_process]
                files.add(r_name)
                edges.add((process, r_name, r_mode, None))

        elif event_type == 'exec':
            r_name, r_timestamp, r_process, r_argv = data
            r_name = PosixPath(r_name)
            process = processes[r_process]
            binaries.add(r_name)
            # Here we split this process in two "programs", unless the previous
            # one hasn't done anything since it was created via fork()
            if not all_forks and not process.acted:
                process.binary = r_name
                process.created = C_FORKEXEC
                process.acted = True
            else:
                process = Process(process.pid,
                                  process,
                                  r_timestamp,
                                  True,         # Hides exec only once
                                  r_name,
                                  C_EXEC)
                all_programs.append(process)
                processes[r_process] = process
            argv = tuple(r_argv.split('\0'))
            if not argv[-1]:
                argv = argv[:-1]
            edges.add((process, r_name, None, argv))

    process_cursor.close()
    file_cursor.close()
    conn.close()

    # Puts files in packages
    logging.info("Organizes packages...")
    package_files = {}
    other_files = []
    for f in files:
        pkg = packages.get(f)
        if pkg is not None:
            package_files.setdefault((pkg.name, pkg.version), []).append(f)
        else:
            other_files.append(f)

    # Writes DOT file
    with target.open('w', encoding='utf-8', newline='\n') as fp:
        fp.write('digraph G {\n    /* programs */\n    node [shape=box];\n')
        # Programs
        logging.info("Writing programs...")
        for program in all_programs:
            fp.write('    prog%d [label="%s (%d)"];\n' % (
                     id(program), program.binary or "-", program.pid))
            if program.parent is not None:
                reason = ''
                if program.created == C_FORK:
                    reason = "fork"
                elif program.created == C_EXEC:
                    reason = "exec"
                elif program.created == C_FORKEXEC:
                    reason = "fork+exec"
                fp.write('    prog%d -> prog%d [label="%s"];\n' % (
                         id(program.parent), id(program), reason))

        fp.write('\n    node [shape=ellipse];\n\n    /* system packages */\n')

        # Files from packages
        logging.info("Writing packages...")
        for i, ((name, version), files) in enumerate(iteritems(package_files)):
            fp.write('    subgraph cluster%d {\n        label=' % i)
            if version:
                fp.write('"%s %s";\n' % (escape(name), escape(version)))
            else:
                fp.write('"%s";\n' % escape(name))
            for f in files:
                fp.write('        "%s";\n' % escape(unicode_(f)))
            fp.write('    }\n')

        fp.write('\n    /* other files */\n')

        # Other files
        logging.info("Writing other files...")
        for f in other_files:
            fp.write('    "%s"\n' % escape(unicode_(f)))

        fp.write('\n')

        # Edges
        logging.info("Connecting edges...")
        for prog, f, mode, argv in edges:
            if mode is None:
                fp.write('    "%s" -> prog%d [color=blue, label="%s"];\n' % (
                         escape(unicode_(f)),
                         id(prog),
                         escape(' '.join(argv))))
            elif mode & FILE_WRITE:
                fp.write('    prog%d -> "%s" [color=red];\n' % (
                         id(prog), escape(unicode_(f))))
            elif mode & FILE_READ:
                fp.write('    "%s" -> prog%d [color=green];\n' % (
                         escape(unicode_(f)), id(prog)))

        fp.write('}\n')


def graph(args):
    """graph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in GraphViz DOT
    format.
    """
    if args.pack is not None:
        tmp = Path.tempdir(prefix='reprounzip_')
        try:
            tar = tarfile.open(args.pack, 'r:*')
            f = tar.extractfile('METADATA/version')
            version = f.read()
            f.close()
            if version != b'REPROZIP VERSION 1\n':
                logging.critical("Unknown pack format")
                sys.exit(1)
            try:
                tar.extract('METADATA/config.yml', path=str(tmp))
                tar.extract('METADATA/trace.sqlite3', path=str(tmp))
            except KeyError as e:
                logging.critical("Error extracting from pack: %s", e.args[0])
            generate(Path(args.target[0]),
                     tmp / 'METADATA',
                     args.all_forks)
        finally:
            tmp.rmtree()
    else:
        generate(Path(args.target[0]), Path(args.dir), args.all_forks)


def disabled_bug13676(args):
    sys.stderr.write("Error: your version of Python, %s, is not "
                     "supported\nVersions before 2.7.3 are affected by bug "
                     "13676 and will not work be able to\nread the trace "
                     "database\n" % sys.version.split(' ', 1)[0])
    sys.exit(1)


def setup(parser, **kwargs):
    """Generates a provenance graph from the trace data
    """

    # http://bugs.python.org/issue13676
    # This prevents repro(un)zip from reading argv and envp arrays from trace
    if sys.version_info < (2, 7, 3):
        parser.add_argument('rest_of_cmdline', nargs=argparse.REMAINDER,
                            help=argparse.SUPPRESS)
        parser.set_defaults(func=disabled_bug13676)
        return {'test_compatibility': (COMPAT_NO, "Python >2.7.3 required")}

    parser.add_argument('target', nargs=1, help="Destination DOT file")
    parser.add_argument('-F', '--all-forks', action='store_true',
                        help="Show forked processes before they exec")
    parser.add_argument(
            '-d', '--dir', default='.reprozip-trace',
            help="where the database and configuration file are stored "
            "(default: ./.reprozip-trace)")
    parser.add_argument(
            'pack', nargs=argparse.OPTIONAL,
            help="Pack to extract (defaults to reading from --dir)")
    parser.set_defaults(func=graph)

    return {'test_compatibility': COMPAT_OK}
