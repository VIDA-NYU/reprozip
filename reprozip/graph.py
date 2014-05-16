from __future__ import unicode_literals

import heapq
import os
import sqlite3
import sys

from reprozip import _pytracer
from reprozip.orderedset import OrderedSet
from reprozip.tracer.common import load_config
from reprozip.utils import CommonEqualityMixin, escape


C_INITIAL   = 0 # First process or don't know
C_FORK      = 1 # Might actually be any one of fork, vfork or clone
C_EXEC      = 2 # Replaced image with execve
C_FORKEXEC  = 3 # A fork then an exec, folded as one because all_forks==False


class Process(CommonEqualityMixin):
    def __init__(self, pid, parent, timestamp, acted, binary, created):
        self.pid = pid
        self.parent = parent
        self.timestamp = timestamp
        self.acted = acted      # Whether that process has done
                                # something yet. If it execve()s
                                # and hasn't done anything since it
                                # forked, no need for it to appear
        self.binary = binary    # Executable file
        self.created = created  # How was this process created, one
                                # of the C_* constants

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

    database = os.path.join(directory, 'trace.sqlite3')

    # Reads package ownership from the configuration
    configfile = os.path.join(directory, 'config.yml')
    if not os.path.isfile(configfile):
        sys.stderr.write("Error: Configuration file does not exist!\n"
                         "Did you forget to run 'reprozip trace'?\n"
                         "If not, you might want to use --dir to specify an "
                         "alternate location.\n")
        sys.exit(1)
    runs, packages, other_files = load_config(configfile)
    packages = dict((f.path, pkg) for pkg in packages for f in pkg.files)

    conn = sqlite3.connect(database)

    # This is a bit weird. We need to iterate on all types of events at the
    # same time, ordering by timestamp, so we decorate-sort-undecorate
    # Decoration adds timestamp (for sorting) and tags by event type, one of
    # 'process', 'open' or 'exec'

    # Reads processes from the database
    process_cursor = conn.cursor()
    process_rows = process_cursor.execute('''
            SELECT id, parent, timestamp
            FROM processes
            ORDER BY id
            ''')
    processes = {}
    all_programs = []

    # ... and opened files...
    file_cursor = conn.cursor()
    file_rows = file_cursor.execute('''
            SELECT name, timestamp, mode, process
            FROM opened_files
            ORDER BY id
            ''')
    binaries = set()
    files = OrderedSet()
    edges = OrderedSet()

    # ... as well as executed files.
    exec_cursor = conn.cursor()
    exec_rows = exec_cursor.execute('''
            SELECT name, timestamp, process, argv
            FROM executed_files
            ORDER BY id
            ''')

    # Loop on all event lists
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
            process = processes[r_process]
            files.add(r_name)
            edges.add((process, r_name, r_mode, None))

        elif event_type == 'exec':
            r_name, r_timestamp, r_process, r_argv = data
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
            edges.add((process, r_name, None, argv))

    process_cursor.close()
    file_cursor.close()
    conn.close()

    # Puts files in packages
    package_files = {}
    other_files = []
    for f in files:
        pkg = packages.get(f)
        if pkg is not None:
            package_files.setdefault((pkg.name, pkg.version), []).append(f)
        else:
            other_files.append(f)

    # Writes DOT file
    with open(target, 'w') as fp:
        fp.write('digraph G {\n    /* programs */\n    node [shape=box];\n')
        # Programs
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
        for i, ((name, version), files) in enumerate(package_files.items()):
            fp.write('    subgraph cluster%d {\n        label=' % i)
            if version:
                fp.write('"%s %s";\n' % (escape(name), escape(version)))
            else:
                fp.write('"%s";\n' % escape(name))
            for f in files:
                fp.write('        "%s";\n' % escape(f))
            fp.write('    }\n')

        fp.write('\n    /* other files */\n')

        # Other files
        for f in other_files:
            fp.write('    "%s"\n' % escape(f))

        fp.write('\n')

        # Edges
        for prog, f, mode, argv in edges:
            if mode is None:
                fp.write('    "%s" -> prog%d [color=blue, label="%s"];\n' % (
                         escape(f), id(prog), escape(' '.join(argv))))
            elif mode & _pytracer.FILE_WRITE:
                fp.write('    prog%d -> "%s" [color=red];\n' % (
                         id(prog), escape(f)))
            else:
                fp.write('    "%s" -> prog%d [color=green];\n' % (
                         escape(f), id(prog)))

        fp.write('}\n')
