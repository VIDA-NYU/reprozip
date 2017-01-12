# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

from rpaths import Path
import sqlite3

from reprounzip.utils import PY3


def make_database(insert, path=None):
    if path is not None:
        path = Path(path)
        if PY3:
            # On PY3, connect() only accepts unicode
            conn = sqlite3.connect(str(path))
        else:
            conn = sqlite3.connect(path.path)
    else:
        conn = sqlite3.connect('')
    conn.row_factory = sqlite3.Row

    conn.execute(
        '''
        CREATE TABLE processes(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            parent INTEGER,
            timestamp INTEGER NOT NULL,
            is_thread BOOLEAN NOT NULL,
            exitcode INTEGER
            );
        ''')
    conn.execute(
        '''
        CREATE INDEX proc_parent_idx ON processes(parent);
        ''')
    conn.execute(
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
        ''')
    conn.execute(
        '''
        CREATE INDEX open_proc_idx ON opened_files(process);
        ''')
    conn.execute(
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
        ''')
    conn.execute(
        '''
        CREATE INDEX exec_proc_idx ON executed_files(process);
        ''')

    for timestamp, l in enumerate(insert):
        if l[0] == 'proc':
            ident, parent, is_thread = l[1:]
            conn.execute(
                '''
                INSERT INTO processes(id, run_id, parent, timestamp,
                                      is_thread, exitcode)
                VALUES(?, 0, ?, ?, ?, 0);
                ''',
                (ident, parent, timestamp, is_thread))
        elif l[0] == 'open':
            process, name, is_dir, mode = l[1:]
            conn.execute(
                '''
                INSERT INTO opened_files(run_id, name, timestamp, mode,
                                         is_directory, process)
                VALUES(0, ?, ?, ?, ?, ?);
                ''',
                (name, timestamp, mode, is_dir, process))
        elif l[0] == 'exec':
            process, name, wdir, argv = l[1:]
            conn.execute(
                '''
                INSERT INTO executed_files(run_id, name, timestamp,
                                           process, argv, envp,
                                           workingdir)
                VALUES(0, ?, ?, ?, ?, "", ?);
                ''',
                (name, timestamp, process, argv, wdir))
        else:
            assert False

    conn.commit()
    return conn
