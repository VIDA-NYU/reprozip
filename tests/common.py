# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import contextlib
import logging
from pathlib import Path
import sqlite3

from reprozip_core.common import create_trace_schema


def make_database(insert, path=None):
    if path is not None:
        path = Path(path)
        conn = sqlite3.connect(str(path))  # connect() only accepts str
    else:
        conn = sqlite3.connect('')
    conn.row_factory = sqlite3.Row

    create_trace_schema(conn)

    run = -1
    for timestamp, l in enumerate(insert):
        if l[0] == 'proc':
            ident, parent, is_thread = l[1:]
            if parent is None:
                run += 1
            conn.execute(
                '''
                INSERT INTO processes(id, run_id, parent, timestamp,
                                      is_thread, exitcode)
                VALUES(?, ?, ?, ?, ?, 0);
                ''',
                (ident, run, parent, timestamp, is_thread))
        elif l[0] == 'exit':
            ident, = l[1:]
            conn.execute(
                '''
                UPDATE processes SET exit_timestamp=?
                WHERE id=?;
                ''',
                (timestamp, ident))
        elif l[0] == 'open':
            process, name, is_dir, mode = l[1:]
            conn.execute(
                '''
                INSERT INTO opened_files(run_id, name, timestamp, mode,
                                         is_directory, process)
                VALUES(?, ?, ?, ?, ?, ?);
                ''',
                (run, name, timestamp, mode, is_dir, process))
        elif l[0] == 'exec':
            process, name, wdir, argv = l[1:]
            conn.execute(
                '''
                INSERT INTO executed_files(run_id, name, timestamp,
                                           process, argv, envp,
                                           workingdir)
                VALUES(?, ?, ?, ?, ?, "", ?);
                ''',
                (run, name, timestamp, process, argv, wdir))
        else:
            assert False

    conn.commit()
    return conn


class _RecorderHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super(_RecorderHandler, self).__init__(level)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@contextlib.contextmanager
def capture_logs(*, logger=logging.root, level=logging.NOTSET):
    recorder = _RecorderHandler()
    handlers = logger.handlers[:]
    try:
        logger.handlers[:] = [recorder]
        yield recorder.records
    finally:
        logger.handlers[:] = handlers
