# Copyright (C) 2014-2017 New York University
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

from __future__ import division, print_function, unicode_literals

import argparse
from distutils.version import LooseVersion
import heapq
import json
import logging
import re
from rpaths import PosixPath, Path
import sqlite3
import sys

from reprounzip.common import FILE_READ, FILE_WRITE, FILE_WDIR, RPZPack, \
    load_config
from reprounzip.orderedset import OrderedSet
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_NO
from reprounzip.utils import PY3, izip, iteritems, itervalues, stderr, \
    unicode_, escape, normalize_path


C_INITIAL = 0   # First process or don't know
C_FORK = 1      # Might actually be any one of fork, vfork or clone
C_EXEC = 2      # Replaced image with execve
C_FORKEXEC = 3  # A fork then an exec, folded as one because all_forks==False


FORMAT_DOT = 0
FORMAT_JSON = 1


LVL_PKG_FILE = 0        # Show individual files in packages
LVL_PKG_PACKAGE = 1     # Aggregate by package
LVL_PKG_IGNORE = 2      # Ignore packages, treat them like any file
LVL_PKG_DROP = 3        # Drop every file that comes from a package

LVL_PROC_THREAD = 0     # Show every process and thread
LVL_PROC_PROCESS = 1    # Only show processes, not threads
LVL_PROC_RUN = 2        # Don't show individual processes, aggregate by run

LVL_OTHER_ALL = 0       # Show every file, aggregate through directory list
LVL_OTHER_IO = 1        # Only show input & output files
LVL_OTHER_NO = 3        # Don't show other files


class Run(object):
    """Structure representing a whole run.
    """
    def __init__(self, nb):
        self.nb = nb
        self.name = "run %d" % nb
        self.processes = []

    def dot(self, fp, level_processes):
        assert self.processes
        if level_processes == LVL_PROC_RUN:
            fp.write('    run%d [label="%d: %s"];\n' % (
                     self.nb, self.nb, self.processes[0].binary or "-"))
        else:
            fp.write('    subgraph cluster_run%d {\n        label="%s";\n' % (
                     self.nb, escape(self.name)))
            for process in self.processes:
                if level_processes == LVL_PROC_THREAD or not process.thread:
                    process.dot(fp, level_processes, indent=2)
            fp.write('    }\n')

    def dot_endpoint(self, level_processes):
        return 'run%d' % self.nb

    def json(self, prog_map, level_processes):
        assert self.processes
        if level_processes == LVL_PROC_RUN:
            json_process = self.processes[0].json()
            for process in self.processes:
                prog_map[process] = json_process
            return [json_process]
        else:
            run = []
            process_idx_map = {}
            for process in self.processes:
                if level_processes == LVL_PROC_THREAD or not process.thread:
                    process_idx_map[process] = len(run)
                    json_process = process.json(process_idx_map)
                    prog_map[process] = json_process
                    run.append(json_process)
                else:
                    p_process = process
                    while p_process.thread:
                        p_process = p_process.parent
                    prog_map[process] = prog_map[p_process]
            return run


class Process(object):
    """Structure representing a process in the experiment.
    """
    _id_gen = 0

    def __init__(self, pid, run, parent, timestamp, thread, acted, binary,
                 created):
        self.id = Process._id_gen
        Process._id_gen += 1
        self.pid = pid
        self.run = run
        self.parent = parent
        self.timestamp = timestamp
        self.thread = thread
        # Whether that process has done something yet. If it execve()s and
        # hasn't done anything since it forked, no need for it to appear
        self.acted = acted
        # Executable file
        self.binary = binary
        # How was this process created, one of the C_* constants
        self.created = created

    def dot(self, fp, level_processes, indent=1):
        thread_style = ',fillcolor="#666666"' if self.thread else ''
        fp.write('    ' * indent + 'prog%d [label="%s (%d)"%s];\n' % (
                 self.id, escape(unicode_(self.binary) or "-"),
                 self.pid, thread_style))
        if self.parent is not None:
            reason = ''
            if self.created == C_FORK:
                if self.thread:
                    reason = "thread"
                else:
                    reason = "fork"
            elif self.created == C_EXEC:
                reason = "exec"
            elif self.created == C_FORKEXEC:
                reason = "fork+exec"
            fp.write('    ' * indent + 'prog%d -> prog%d [label="%s"];\n' % (
                     self.parent.id, self.id, reason))

    def dot_endpoint(self, level_processes):
        if level_processes == LVL_PROC_RUN:
            return self.run.dot_endpoint(level_processes)
        else:
            prog = self
            if level_processes == LVL_PROC_PROCESS:
                while prog.thread:
                    prog = prog.parent
            return 'prog%d' % prog.id

    def json(self, process_map):
        name = "%d" % self.pid
        long_name = "%s (%d)" % (PosixPath(self.binary).components[-1]
                                 if self.binary else "-",
                                 self.pid)
        description = "%s\n%d" % (self.binary, self.pid)
        if self.parent is not None:
            if self.created == C_FORK:
                reason = "fork"
            elif self.created == C_EXEC:
                reason = "exec"
            elif self.created == C_FORKEXEC:
                reason = "fork+exec"
            else:
                assert False
            parent = [process_map[self.parent], reason]
        else:
            parent = None
        return {'name': name, 'parent': parent, 'reads': [], 'writes': [],
                'long_name': long_name, 'description': description}


class Package(object):
    """Structure representing a system package.
    """
    def __init__(self, name, version=None):
        self.id = None
        self.name = name
        self.version = version
        self.files = set()

    def dot(self, fp, level_pkgs):
        assert self.id is not None
        if not self.files:
            return

        if level_pkgs == LVL_PKG_PACKAGE:
            fp.write('    "pkg %s" [shape=box,label=' % escape(self.name))
            if self.version:
                fp.write('"%s %s"];\n' % (
                         escape(self.name), escape(self.version)))
            else:
                fp.write('"%s"];\n' % escape(self.name))
        elif level_pkgs == LVL_PKG_FILE:
            fp.write('    subgraph cluster_pkg%d {\n        label=' % self.id)
            if self.version:
                fp.write('"%s %s";\n' % (
                         escape(self.name), escape(self.version)))
            else:
                fp.write('"%s";\n' % escape(self.name))
            for f in sorted(unicode_(f) for f in self.files):
                fp.write('        "%s";\n' % escape(f))
            fp.write('    }\n')

    def dot_endpoint(self, f, level_pkgs):
        if level_pkgs == LVL_PKG_PACKAGE:
            return '"pkg %s"' % escape(self.name)
        else:
            return '"%s"' % escape(unicode_(f))

    def json(self, level_pkgs):
        if level_pkgs == LVL_PKG_PACKAGE:
            logging.critical("JSON output doesn't support --packages package")
            sys.exit(1)
        elif level_pkgs == LVL_PKG_FILE:
            files = sorted(unicode_(f) for f in self.files)
        else:
            assert False
        return {'name': self.name, 'version': self.version or None,
                'files': files}


def parse_levels(level_pkgs, level_processes, level_other_files):
    try:
        level_pkgs = {'file': LVL_PKG_FILE,
                      'files': LVL_PKG_FILE,
                      'package': LVL_PKG_PACKAGE,
                      'packages': LVL_PKG_PACKAGE,
                      'ignore': LVL_PKG_IGNORE,
                      'drop': LVL_PKG_DROP}[level_pkgs]
    except KeyError:
        logging.critical("Unknown level of detail for packages: '%s'",
                         level_pkgs)
        sys.exit(1)
    try:
        level_processes = {'thread': LVL_PROC_THREAD,
                           'threads': LVL_PROC_THREAD,
                           'process': LVL_PROC_PROCESS,
                           'processes': LVL_PROC_PROCESS,
                           'run': LVL_PROC_RUN,
                           'runs': LVL_PROC_RUN}[level_processes]
    except KeyError:
        logging.critical("Unknown level of detail for processes: '%s'",
                         level_processes)
        sys.exit(1)
    if level_other_files.startswith('depth:'):
        file_depth = int(level_other_files[6:])
        level_other_files = 'all'
    else:
        file_depth = None
    try:
        level_other_files = {'all': LVL_OTHER_ALL,
                             'io': LVL_OTHER_IO,
                             'inputoutput': LVL_OTHER_IO,
                             'no': LVL_OTHER_NO,
                             'none': LVL_OTHER_NO,
                             'drop': LVL_OTHER_NO}[level_other_files]
    except KeyError:
        logging.critical("Unknown level of detail for other files: '%s'",
                         level_other_files)
        sys.exit(1)

    return level_pkgs, level_processes, level_other_files, file_depth


def read_events(database, all_forks, has_thread_flag):
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

    if PY3:
        # On PY3, connect() only accepts unicode
        conn = sqlite3.connect(str(database))
    else:
        conn = sqlite3.connect(database.path)
    conn.row_factory = sqlite3.Row

    # This is a bit weird. We need to iterate on all types of events at the
    # same time, ordering by timestamp, so we decorate-sort-undecorate
    # Decoration adds timestamp (for sorting) and tags by event type, one of
    # 'process', 'open' or 'exec'

    # Reads processes from the database
    process_cursor = conn.cursor()
    if has_thread_flag:
        sql = '''
        SELECT id, parent, timestamp, is_thread
        FROM processes
        ORDER BY id
        '''
    else:
        sql = '''
        SELECT id, parent, timestamp, 0 as is_thread
        FROM processes
        ORDER BY id
        '''
    process_rows = process_cursor.execute(sql)
    processes = {}
    all_programs = []

    # ... and opened files...
    file_cursor = conn.cursor()
    file_rows = file_cursor.execute(
        '''
        SELECT name, timestamp, mode, process, is_directory
        FROM opened_files
        ORDER BY id
        ''')
    binaries = set()
    files = set()
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
    runs = []
    run = None
    for ts, event_type, data in rows:
        if event_type == 'process':
            r_id, r_parent, r_timestamp, r_thread = data
            logging.debug("Process %d created (parent %r)", r_id, r_parent)
            if r_parent is not None:
                parent = processes[r_parent]
                binary = parent.binary
            else:
                run = Run(len(runs))
                runs.append(run)
                parent = None
                binary = None
            process = Process(r_id,
                              run,
                              parent,
                              r_timestamp,
                              r_thread,
                              False,
                              binary,
                              C_INITIAL if r_parent is None else C_FORK)
            processes[r_id] = process
            all_programs.append(process)
            run.processes.append(process)

        elif event_type == 'open':
            r_name, r_timestamp, r_mode, r_process, r_directory = data
            r_name = normalize_path(r_name)
            logging.debug("File open: %s, process %d", r_name, r_process)
            if not (r_mode & FILE_WDIR or r_directory):
                process = processes[r_process]
                files.add(r_name)
                edges.add((process, r_name, r_mode, None))

        elif event_type == 'exec':
            r_name, r_timestamp, r_process, r_argv = data
            r_name = normalize_path(r_name)
            argv = tuple(r_argv.split('\0'))
            if not argv[-1]:
                argv = argv[:-1]
            logging.debug("File exec: %s, process %d", r_name, r_process)
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
                                  run,
                                  process,
                                  r_timestamp,
                                  False,
                                  True,         # Hides exec only once
                                  r_name,
                                  C_EXEC)
                all_programs.append(process)
                processes[r_process] = process
                run.processes.append(process)
            files.add(r_name)
            edges.add((process, r_name, None, argv))

    process_cursor.close()
    file_cursor.close()
    exec_cursor.close()
    conn.close()

    return runs, files, edges


def format_argv(argv):
    joined = ' '.join(argv)
    if len(joined) < 50:
        return joined
    else:
        return "%s ..." % argv[0]


def generate(target, configfile, database, all_forks=False, graph_format='dot',
             level_pkgs='file', level_processes='thread',
             level_other_files='all',
             regex_filters=None, regex_replaces=None, aggregates=None):
    """Main function for the graph subcommand.
    """
    try:
        graph_format = {'dot': FORMAT_DOT, 'DOT': FORMAT_DOT,
                        'json': FORMAT_JSON, 'JSON': FORMAT_JSON}[graph_format]
    except KeyError:
        logging.critical("Unknown output format %r", graph_format)
        sys.exit(1)

    level_pkgs, level_processes, level_other_files, file_depth = \
        parse_levels(level_pkgs, level_processes, level_other_files)

    # Reads package ownership from the configuration
    if not configfile.is_file():
        logging.critical("Configuration file does not exist!\n"
                         "Did you forget to run 'reprozip trace'?\n"
                         "If not, you might want to use --dir to specify an "
                         "alternate location.")
        sys.exit(1)
    config = load_config(configfile, canonical=False)
    inputs_outputs = dict((f.path, n)
                          for n, f in iteritems(config.inputs_outputs))
    has_thread_flag = config.format_version >= LooseVersion('0.7')

    runs, files, edges = read_events(database, all_forks,
                                     has_thread_flag)

    # Label the runs
    if len(runs) != len(config.runs):
        logging.warning("Configuration file doesn't list the same number of "
                        "runs we found in the database!")
    else:
        for config_run, run in izip(config.runs, runs):
            run.name = config_run['id']

    # Apply regexes
    ignore = [lambda path, r=re.compile(p): r.search(path) is not None
              for p in regex_filters or []]
    replace = [lambda path, r=re.compile(p): r.sub(repl, path)
               for p, repl in regex_replaces or []]

    def filefilter(path):
        pathuni = unicode_(path)
        if any(f(pathuni) for f in ignore):
            logging.debug("IGN %s", pathuni)
            return None
        if not (replace or aggregates):
            return path
        for fi in replace:
            pathuni_ = fi(pathuni)
            if pathuni_ != pathuni:
                logging.debug("SUB %s -> %s", pathuni, pathuni_)
            pathuni = pathuni_
        for prefix in aggregates or []:
            if pathuni.startswith(prefix):
                logging.debug("AGG %s -> %s", pathuni, prefix)
                pathuni = prefix
                break
        return PosixPath(pathuni)

    files_new = set()
    for fi in files:
        fi = filefilter(fi)
        if fi is not None:
            files_new.add(fi)
    files = files_new

    edges_new = OrderedSet()
    for prog, fi, mode, argv in edges:
        fi = filefilter(fi)
        if fi is not None:
            edges_new.add((prog, fi, mode, argv))
    edges = edges_new

    # Puts files in packages
    package_map = {}
    if level_pkgs == LVL_PKG_IGNORE:
        packages = []
        other_files = files
    else:
        logging.info("Organizes packages...")
        file2package = dict((f.path, pkg)
                            for pkg in config.packages for f in pkg.files)
        packages = {}
        other_files = []
        for fi in files:
            pkg = file2package.get(fi)
            if pkg is not None:
                package = packages.get(pkg.name)
                if package is None:
                    package = Package(pkg.name, pkg.version)
                    packages[pkg.name] = package
                package.files.add(fi)
                package_map[fi] = package
            else:
                other_files.append(fi)
        packages = sorted(itervalues(packages), key=lambda pkg: pkg.name)
        for i, pkg in enumerate(packages):
            pkg.id = i

    # Filter other files
    if level_other_files == LVL_OTHER_ALL and file_depth is not None:
        other_files = set(PosixPath(*f.components[:file_depth + 1])
                          for f in other_files)
        edges = OrderedSet((prog,
                            f if f in package_map
                            else PosixPath(*f.components[:file_depth + 1]),
                            mode,
                            argv)
                           for prog, f, mode, argv in edges)
    else:
        if level_other_files == LVL_OTHER_IO:
            other_files = set(f for f in other_files if f in inputs_outputs)
            edges = [(prog, f, mode, argv)
                     for prog, f, mode, argv in edges
                     if f in package_map or f in other_files]
        elif level_other_files == LVL_OTHER_NO:
            other_files = set()
            edges = [(prog, f, mode, argv)
                     for prog, f, mode, argv in edges
                     if f in package_map]

    args = (target, runs, packages, other_files, package_map, edges,
            inputs_outputs, level_pkgs, level_processes, level_other_files)
    if graph_format == FORMAT_DOT:
        graph_dot(*args)
    elif graph_format == FORMAT_JSON:
        graph_json(*args)
    else:
        assert False


def graph_dot(target, runs, packages, other_files, package_map, edges,
              inputs_outputs, level_pkgs, level_processes, level_other_files):
    """Writes a GraphViz DOT file from the collected information.
    """
    with target.open('w', encoding='utf-8', newline='\n') as fp:
        fp.write('digraph G {\n    /* programs */\n'
                 '    node [shape=box fontcolor=white '
                 'fillcolor=black style=filled];\n')

        # Programs
        logging.info("Writing programs...")
        for run in runs:
            run.dot(fp, level_processes)

        fp.write('\n'
                 '    node [shape=ellipse fontcolor="#131C39" '
                 'fillcolor="#C9D2ED"];\n')

        # Packages
        if level_pkgs not in (LVL_PKG_IGNORE, LVL_PKG_DROP):
            logging.info("Writing packages...")
            fp.write('\n    /* system packages */\n')
            for package in sorted(packages, key=lambda pkg: pkg.name):
                package.dot(fp, level_pkgs)

        fp.write('\n    /* other files */\n')

        # Other files
        logging.info("Writing other files...")
        for fi in sorted(other_files):
            if fi in inputs_outputs:
                fp.write('    "%(path)s" [fillcolor="#A3B4E0", '
                         'label="%(name)s\\n%(path)s"];\n' %
                         {'path': escape(unicode_(fi)),
                          'name': inputs_outputs[fi]})
            else:
                fp.write('    "%s";\n' % escape(unicode_(fi)))

        fp.write('\n')

        # Edges
        logging.info("Connecting edges...")
        done_edges = set()
        for prog, fi, mode, argv in edges:
            endp_prog = prog.dot_endpoint(level_processes)
            if fi in package_map:
                if level_pkgs == LVL_PKG_DROP:
                    continue
                endp_file = package_map[fi].dot_endpoint(fi, level_pkgs)
                e = endp_prog, endp_file, mode
                if e in done_edges:
                    continue
                else:
                    done_edges.add(e)
            else:
                endp_file = '"%s"' % escape(unicode_(fi))

            if mode is None:
                fp.write('    %s -> %s [style=bold, label="%s"];\n' % (
                         endp_file,
                         endp_prog,
                         escape(format_argv(argv))))
            elif mode & FILE_WRITE:
                fp.write('    %s -> %s [color="#000088"];\n' % (
                         endp_prog, endp_file))
            elif mode & FILE_READ:
                fp.write('    %s -> %s [color="#8888CC"];\n' % (
                         endp_file, endp_prog))

        fp.write('}\n')


def graph_json(target, runs, packages, other_files, package_map, edges,
               inputs_outputs, level_pkgs, level_processes, level_other_files):
    """Writes a JSON file suitable for further processing.
    """
    # Packages
    json_packages = [pkg.json(level_pkgs) for pkg in packages]

    # Other files
    json_other_files = [unicode_(fi) for fi in sorted(other_files)]

    # Programs
    prog_map = {}
    json_runs = [run.json(prog_map, level_processes) for run in runs]

    # Connect edges
    for prog, f, mode, argv in edges:
        what = unicode_(f)
        if mode is None:
            prog_map[prog]['reads'].append(what)
            # TODO: argv?
        elif mode & FILE_WRITE:
            prog_map[prog]['writes'].append(what)
        elif mode & FILE_READ:
            prog_map[prog]['reads'].append(what)

    json_other_files.sort()

    if PY3:
        fp = target.open('w', encoding='utf-8', newline='\n')
    else:
        fp = target.open('wb')
    try:
        json.dump({'packages': sorted(json_packages,
                                      key=lambda p: p['name']),
                   'other_files': json_other_files,
                   'runs': json_runs},
                  fp,
                  ensure_ascii=False,
                  indent=2,
                  sort_keys=True)
    finally:
        fp.close()


def graph(args):
    """graph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in GraphViz DOT
    format or JSON.
    """
    def call_generate(args, config, trace):
        generate(Path(args.target[0]), config, trace, args.all_forks,
                 args.format, args.packages, args.processes, args.otherfiles,
                 args.regex_filter, args.regex_replace, args.aggregate)

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
    parser.add_argument('--packages', default='file',
                        help="Level of detail for packages; 'file', "
                        "'package', 'drop' or 'ignore' (default: 'file')")
    parser.add_argument('--processes', default='thread',
                        help="Level of detail for processes; 'thread', "
                        "'process' or 'run' (default: 'thread')")
    parser.add_argument('--otherfiles', default='all',
                        help="Level of detail for non-package files; 'all', "
                        "'io' or 'no' (default: 'all')")
    parser.add_argument('--aggregate', action='append',
                        help="Aggregate all files under this path")
    parser.add_argument('--regex-filter', action='append',
                        help="Glob patterns of files to ignore")
    parser.add_argument('--regex-replace', action='append', nargs=2,
                        help="Apply regular expression replacement to files")
    parser.add_argument('--dot', action='store_const', dest='format',
                        const='dot', default='dot',
                        help="Set the output format to DOT (this is the "
                        "default)")
    parser.add_argument('--json', action='store_const', dest='format',
                        const='json', help="Set the output format to JSON")
    parser.add_argument(
        '-d', '--dir', default='.reprozip-trace',
        help="where the database and configuration file are stored (default: "
        "./.reprozip-trace)")
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to extract (defaults to reading from --dir)")
    parser.set_defaults(func=graph)

    return {'test_compatibility': COMPAT_OK}
