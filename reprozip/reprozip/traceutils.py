# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Additional manipulations for traces.

These are operations on traces that are not directly related to the tracing
process itself.
"""

import logging
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

from reprozip_core.common import create_trace_schema, File


logger = logging.getLogger('reprozip')


def combine_files(new_files, new_package_envs, old_files, old_package_envs):
    """Merges two sets of packages and files.
    """
    files = set(old_files)
    files.update(new_files)

    packages = dict((pkg.name, pkg) for pkg in new_package_envs)
    for old_pkg in old_package_envs:
        if old_pkg.name in packages:
            pkg = packages[old_pkg.name]
            s = set(File.from_local(fi.path) for fi in old_pkg.files)
            s.update(pkg.files)
            old_pkg.files = list(s)
            packages[old_pkg.name] = old_pkg
        else:
            old_pkg.files = [File.from_local(fi.path) for fi in old_pkg.files]
            packages[old_pkg.name] = old_pkg
    packages = packages.values()

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
    # We are probably overwriting one of the traces we're reading, so write to
    # a temporary file first then move it
    fd, output = tempfile.mkstemp('.sqlite3', 'reprozip_combined_')
    output = Path(output)
    conn = sqlite3.connect(str(output))  # connect() only accepts str
    os.close(fd)
    conn.row_factory = sqlite3.Row

    # Create the schema
    create_trace_schema(conn)

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
    for other in traces:
        logger.info("Attaching database %s", other)

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
            FROM trace.processes
            ORDER BY run_id;
            ''')

        logger.info(
            "%d rows in maps.map_runs",
            list(conn.execute('SELECT COUNT(*) FROM maps.map_runs;'))[0][0])

        # Add processes to lookup table
        conn.execute(
            '''
            INSERT INTO maps.map_processes(old)
            SELECT id AS old
            FROM trace.processes
            ORDER BY id;
            ''')

        logger.info(
            "%d rows in maps.map_processes",
            list(conn.execute('SELECT COUNT(*) FROM maps.map_processes;'))
            [0][0])

        # processes
        logger.info("Insert processes...")
        conn.execute(
            '''
            INSERT INTO processes(id, run_id, parent, timestamp,
                                  exit_timestamp, cpu_time, is_thread,
                                  exitcode)
            SELECT p.new AS id, r.new AS run_id, parent,
                   timestamp, exit_timestamp, cpu_time, is_thread, exitcode
            FROM trace.processes t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.id = p.old
            ORDER BY t.id;
            ''')

        # opened_files
        logger.info("Insert opened_files...")
        conn.execute(
            '''
            INSERT INTO opened_files(run_id, name, timestamp,
                                     mode, is_directory, process)
            SELECT r.new AS run_id, name, timestamp,
                   mode, is_directory, p.new AS process
            FROM trace.opened_files t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.process = p.old
            ORDER BY t.id;
            ''')

        # executed_files
        logger.info("Insert executed_files...")
        conn.execute(
            '''
            INSERT INTO executed_files(name, run_id, timestamp, process,
                                       argv, envp, workingdir)
            SELECT name, r.new AS run_id, timestamp, p.new AS process,
                   argv, envp, workingdir
            FROM trace.executed_files t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.process = p.old
            ORDER BY t.id;
            ''')

        # connections
        logger.info("Insert connections...")
        conn.execute(
            '''
            INSERT INTO connections(run_id, timestamp, process, inbound,
                                    family, protocol, address)
            SELECT r.new AS run_id, timestamp, p.new AS process,
                   inbound, family, protocol, address
            FROM trace.connections t
            INNER JOIN maps.map_runs r ON t.run_id = r.old
            INNER JOIN maps.map_processes p ON t.process = p.old
            ORDER BY t.id;
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

        # An implicit transaction gets created. Python used to implicitly
        # commit it, but no longer does as of 3.6, so we have to explicitly
        # commit before detaching.
        conn.commit()

        # Detach
        conn.execute(
            '''
            DETACH DATABASE trace;
            ''')

    # See above.
    conn.commit()

    conn.execute(
        '''
        DETACH DATABASE maps;
        ''')

    conn.commit()
    conn.close()

    # Move database to final destination
    target.mkdir(exist_ok=True)
    shutil.move(output, target / 'trace.sqlite3')
