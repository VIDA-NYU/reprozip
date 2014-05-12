from __future__ import unicode_literals

from collections import namedtuple
import heapq
import os
import sqlite3

from reprozip import _pytracer
from reprozip.orderedset import OrderedSet
from reprozip.utils import compat_execfile, CommonEqualityMixin


C_INITIAL   = 0 # First process or don't know
C_FORK      = 1 # Might actually be any one of fork, vfork or clone
C_EXEC      = 2 # Replaced image with execve
C_FORKEXEC  = 3 # A fork then an exec, folded as one because all_forks==False


File = namedtuple('File', ['path'])
Package = namedtuple('Package', ['name', 'version', 'files', 'packfiles',
                                 'size'])


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


def escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


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
    packages = {}
    configfile = os.path.join(directory, 'config.py')
    config = {}
    if os.path.isfile(configfile):
        compat_execfile(configfile,
                        {'Package': Package, 'File': File},
                        config)
    for pkg in config.get('packages', []):
        for f in pkg.files:
            packages[f.path] = pkg

    conn = sqlite3.connect(database)

    # Reads processes from the database
    process_cursor = conn.cursor()
    process_rows = process_cursor.execute('''
            SELECT id, parent, timestamp
            FROM processes
            ORDER BY id
            ''')
    processes = {}
    all_programs = []

    # ... and files. At the same time.
    file_cursor = conn.cursor()
    file_rows = file_cursor.execute('''
            SELECT name, timestamp, mode, process
            FROM opened_files
            ORDER BY id
            ''')
    binaries = set()
    files = OrderedSet()
    edges = OrderedSet()

    # Loop on both event lists
    rows = heapq.merge(((r[2], 'process', r) for r in process_rows),
                       ((r[1], 'file', r) for r in file_rows))
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

        elif event_type == 'file':
            r_name, r_timestamp, r_mode, r_process = data
            process = processes[r_process]
            if r_mode == _pytracer.FILE_EXEC:
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
                edges.add((process, r_name, r_mode))
            else:
                files.add(r_name)
                edges.add((process, r_name, r_mode))

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
        for prog, f, mode in edges:
            if mode & _pytracer.FILE_EXEC:
                fp.write('    "%s" -> prog%d [color=blue];\n' % (
                         escape(f), id(prog)))
            elif mode & _pytracer.FILE_WRITE:
                fp.write('    prog%d -> "%s" [color=red];\n' % (
                         id(prog), escape(f)))
            else:
                fp.write('    "%s" -> prog%d [color=green];\n' % (
                         escape(f), id(prog)))

        fp.write('}\n')
