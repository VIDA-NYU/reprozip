# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import os
from rpaths import Path
import sqlite3
import sys
import unittest

from reprozip.common import FILE_READ, FILE_WRITE, FILE_WDIR, InputOutputFile
from reprozip.tracer.trace import get_files, compile_inputs_outputs
from reprozip.utils import UniqueNames, make_dir_writable


class TestReprozip(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'chown'), "No POSIX file permissions")
    def test_make_dir_writable(self):
        """Tests make_dir_writable with read-only dir."""
        def check_mode(mod, path):
            self.assertEqual(oct((path.stat().st_mode & 0o0700) >> 6),
                             oct(mod))

        tmp = Path.tempdir()
        try:
            (tmp / 'some' / 'path').mkdir(parents=True)
            (tmp / 'some' / 'path').chmod(0o555)
            with make_dir_writable(tmp / 'some' / 'path'):
                check_mode(7, tmp / 'some')
                check_mode(7, tmp / 'some' / 'path')
            check_mode(7, tmp / 'some')
            check_mode(5, tmp / 'some' / 'path')
        finally:
            (tmp / 'some').chmod(0o755)
            (tmp / 'some' / 'path').chmod(0o755)
            tmp.rmtree()

    @unittest.skipUnless(hasattr(os, 'chown'), "No POSIX file permissions")
    def test_make_dir_writable2(self):
        """Tests make_dir_writable with read-only and no-executable dirs."""
        def check_mode(mod, path):
            self.assertEqual(oct((path.stat().st_mode & 0o0700) >> 6),
                             oct(mod))

        tmp = Path.tempdir()
        try:
            (tmp / 'some' / 'complete' / 'path').mkdir(parents=True)
            (tmp / 'some' / 'complete' / 'path').chmod(0o555)
            (tmp / 'some' / 'complete').chmod(0o444)
            with make_dir_writable(tmp / 'some' / 'complete' / 'path'):
                check_mode(7, tmp / 'some')
                check_mode(7, tmp / 'some' / 'complete')
                check_mode(7, tmp / 'some' / 'complete' / 'path')
            check_mode(7, tmp / 'some')
            check_mode(4, tmp / 'some' / 'complete')
            (tmp / 'some' / 'complete').chmod(0o755)
            check_mode(5, tmp / 'some' / 'complete' / 'path')
        finally:
            (tmp / 'some').chmod(0o755)
            (tmp / 'some' / 'complete').chmod(0o755)
            (tmp / 'some' / 'complete' / 'path').chmod(0o755)
            tmp.rmtree()

    @unittest.skipIf(sys.version_info < (2, 7, 3),
                     "Python version not supported by reprozip")
    def test_argparse(self):
        """Tests argument parsing"""
        calls = []

        def testrun(args):
            calls.append(('t', args.verbosity))

        def setup_logging(tag, verbosity):
            calls.append(('l', verbosity))

        import reprozip.main

        old_funcs = reprozip.main.testrun, reprozip.main.setup_logging
        reprozip.main.testrun = testrun
        reprozip.main.setup_logging = setup_logging
        old_argv = sys.argv
        print("<<<<< argparse tests for reprozip (disregard usage warnings)",
              file=sys.stderr)
        try:
            for a, c, v in [('reprozip', 2, -1),
                            ('reprozip -v', 2, -1),
                            ('reprozip testrun true', 0, 1),
                            ('reprozip testrun -v true', 2, -1),
                            ('reprozip -v testrun true', 0, 2),
                            ('reprozip -v -v testrun true', 0, 3)]:
                sys.argv = a.split()
                with self.assertRaises(SystemExit) as cm:
                    reprozip.main.main(setup_streams=False)
                if isinstance(cm.exception, int):
                    # Python 2.6: cm.exception is an int (what!?)
                    self.assertEqual(cm.exception, c)
                else:
                    # Working Python versions
                    self.assertEqual(cm.exception.code, c)
                if c == 0:
                    self.assertEqual(calls, [('l', v), ('t', v)])
                calls = []
        finally:
            print(">>>>> argparse tests", file=sys.stderr)
            sys.argv = old_argv
            reprozip.main.testrun, reprozip.main.setup_logging = old_funcs


class TestNames(unittest.TestCase):
    def test_uniquenames(self):
        """Tests UniqueNames."""
        u = UniqueNames()
        self.assertEqual(u('test'), 'test')
        self.assertEqual(u('test'), 'test_2')
        self.assertEqual(u('test'), 'test_3')
        self.assertEqual(u('test_2'), 'test_2_2')
        self.assertEqual(u('test_'), 'test_')
        self.assertEqual(u('test_'), 'test__2')

    def test_label_files(self):
        """Tests input/output file labelling."""
        wd = Path('/fakeworkingdir')
        self.assertEqual(
                compile_inputs_outputs(
                    [{'argv': ['aa', 'bb.txt'], 'workingdir': wd}],
                    [[wd / 'aa', Path('/other/cc.bin'), wd / 'bb.txt']],
                    [[]]),
                {'arg0': InputOutputFile(wd / 'aa', [0], []),
                 'cc.bin': InputOutputFile(Path('/other/cc.bin'), [0], []),
                 'arg1': InputOutputFile(wd / 'bb.txt', [0], [])})


class TestFiles(unittest.TestCase):
    def do_test(self, insert):
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
                ident, parent, = l[1:]
                conn.execute(
                        '''
                        INSERT INTO processes(id, run_id, parent, timestamp,
                                              is_thread, exitcode)
                        VALUES(?, 0, ?, ?, 0, 0);
                        ''',
                        (ident, parent, timestamp))
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
                process, name, wdir = l[1:]
                conn.execute(
                        '''
                        INSERT INTO executed_files(run_id, name, timestamp,
                                                   process, argv, envp,
                                                   workingdir)
                        VALUES(0, ?, ?, ?, "ls", "", ?);
                        ''',
                        (name, timestamp, process, wdir))
            else:
                assert False

        try:
            files, inputs, outputs = get_files(conn)
            files = set(fi for fi in files
                        if not fi.path.path.startswith(b'/lib'))
            return files, inputs, outputs
        finally:
            conn.close()

    def test_get_files(self):
        files, inputs, outputs = self.do_test([
            ('proc', 0, None),
            ('open', 0, "/some/dir", True, FILE_WDIR),
            ('exec', 0, "/some/dir/ls", "/some/dir"),
            ('open', 0, "/some/otherdir/in", False, FILE_READ),
            ('open', 0, "/some/thing/created", True, FILE_WRITE),
            ('open', 0, "/some/thing/created/file", False, FILE_WRITE),
            ('open', 0, "/some/thing/created/file", False, FILE_READ),
            ('open', 0, "/some/thing/created", True, FILE_WDIR),
            ('exec', 0, "/some/thing/created/file", "/some/thing/created"),
        ])
        expected = [
            '/some/dir',
            '/some/dir/ls',
            '/some/otherdir/in',
            '/some/thing',
        ]
        self.assertEqual(set(Path(p) for p in expected),
                         set(fi.path for fi in files))