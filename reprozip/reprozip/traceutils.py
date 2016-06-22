# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Additional manipulations for traces.

These are operations on traces that are not directly related to the tracing
process itself.
"""

import logging
import os
from rpaths import Path
import sqlite3

from reprozip.tracer.trace import TracedFile
from reprozip.utils import PY3, listvalues


def create_schema(conn):
    """Create the trace database schema on a given SQLite3 connection.
    """
    sql = [
        '''
        CREATE TABLE processes(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            parent INTEGER,
            timestamp INTEGER NOT NULL,
            is_thread BOOLEAN NOT NULL,
            exitcode INTEGER
            );
        ''',
        '''
        CREATE INDEX proc_parent_idx ON processes(parent);
        ''',
        '''
        CREATE TABLE opened_files(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            mode INTEGER NOT NULL,
            is_directory BOOLEAN NOT NULL,
            process INTEGER NOT NULL
            );
        ''',
        '''
        CREATE INDEX open_proc_idx ON opened_files(process);
        ''',
        '''
        CREATE TABLE executed_files(
            id INTEGER NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            run_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            process INTEGER NOT NULL,
            argv TEXT NOT NULL,
            envp TEXT NOT NULL,
            workingdir TEXT NOT NULL
            );
        ''',
        '''
        CREATE INDEX exec_proc_idx ON executed_files(process);
        ''',
    ]
    for stmt in sql:
        conn.execute(stmt)


def combine_files(newfiles, newpackages, oldfiles, oldpackages):
    """Merges two sets of packages and files.
    """
    files = set(oldfiles)
    files.update(newfiles)

    packages = dict((pkg.name, pkg) for pkg in newpackages)
    for oldpkg in oldpackages:
        if oldpkg.name in packages:
            pkg = packages[oldpkg.name]
            # Here we build TracedFiles from the Files so that the comment
            # (size, etc) gets set
            s = set(TracedFile(fi.path) for fi in oldpkg.files)
            s.update(pkg.files)
            oldpkg.files = list(s)
            packages[oldpkg.name] = oldpkg
        else:
            oldpkg.files = [TracedFile(fi.path) for fi in oldpkg.files]
            packages[oldpkg.name] = oldpkg
    packages = listvalues(packages)

    return files, packages


def combine_traces(traces, target):
    """Combines multiple trace databases into one.

    The runs from the original traces are appended ('run_id' field gets
    translated to avoid conflicts).

    :param traces: List of trace database filenames.
    :type traces: [Path]
    :param target: Directory where to write the new database and associated
        configuration file.
    :type target: Path
    """
    # We are probably overwriting on of the traces we're reading, so write to
    # a temporary file first then move it
    fd, output = Path.tempfile('.sqlite3', 'reprozip_combined_')
    if PY3:
        # On PY3, connect() only accepts unicode
        conn = sqlite3.connect(str(output))
    else:
        conn = sqlite3.connect(output.path)
    os.close(fd)
    conn.row_factory = sqlite3.Row

    # Create the schema
    create_schema(conn)

    # Temporary database with lookup tables
    conn.execute(
        '''
        ATTACH DATABASE '' AS maps;
        ''')
    conn.execute(
        '''
        CREATE TABLE maps.map_runs(
            old INTEGER NOT NULL,
            new INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
            );
        ''')
    conn.execute(
        '''
        CREATE TABLE maps.map_processes(
            old INTEGER NOT NULL,
            new INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
            );
        ''')

    # Do the merge
    for i, other in enumerate(traces):
        logging.info("Attaching database %s", other)

        # Attach the other trace
        conn.execute(
            '''
            ATTACH DATABASE ? AS trace;
            ''',
            (str(other),))

        # Add runs to lookup table
        conn.execute(
            '''
            INSERT INTO maps.map_runs(old)
            SELECT DISTINCT run_id AS old
            FROM trace.processes;
            ''')

        logging.info(
            "%d rows in maps.map_runs",
            list(conn.execute('SELECT COUNT(*) FROM maps.map_runs;'))[0][0])

        # Add processes to lookup table
        conn.execute(
            '''
            INSERT INTO maps.map_processes(old)
            SELECT id AS old
            FROM trace.processes;
            ''')

        logging.info(
            "%d rows in maps.map_processes",
            list(conn.execute('SELECT COUNT(*) FROM maps.map_processes;'))
            [0][0])

        # processes
        logging.info("Insert processes...")
        conn.execute(
            '''
            INSERT INTO processes(id, run_id, parent,
                                       timestamp, is_thread, exitcode)
            SELECT p.new AS id, r.new AS run_id, parent,
                   timestamp, is_thread, exitcode
            FROM trace.processes t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.id = p.old;
            ''')

        # opened_files
        logging.info("Insert opened_files...")
        conn.execute(
            '''
            INSERT INTO opened_files(run_id, name, timestamp,
                                     mode, is_directory, process)
            SELECT r.new AS run_id, name, timestamp,
                   mode, is_directory, p.new AS process
            FROM trace.opened_files t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.process = p.old;
            ''')

        # executed_files
        logging.info("Insert executed_files...")
        conn.execute(
            '''
            INSERT INTO executed_files(name, run_id, timestamp, process,
                                       argv, envp, workingdir)
            SELECT name, r.new AS run_id, timestamp, p.new AS process,
                   argv, envp, workingdir
            FROM trace.executed_files t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.process = p.old;
            ''')

        # Flush maps
        conn.execute(
            '''
            DELETE FROM maps.map_runs;
            ''')
        conn.execute(
            '''
            DELETE FROM maps.map_processes;
            ''')

        # Detach
        conn.execute(
            '''
            DETACH DATABASE trace;
            ''')

    conn.execute(
        '''
        DETACH DATABASE maps;
        ''')

    conn.commit()
    conn.close()

    # Move database to final destination
    if not target.exists():
        target.mkdir()
    output.move(target / 'trace.sqlite3')
