# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import os
from rpaths import AbstractPath, Path
import sys
import unittest

from reprozip.common import FILE_READ, FILE_WRITE, FILE_WDIR, InputOutputFile
from reprozip.tracer.trace import get_files, compile_inputs_outputs
from reprozip.utils import unicode_, UniqueNames, make_dir_writable

from tests.common import make_database


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
        conn = make_database(insert)

        try:
            files, inputs, outputs = get_files(conn)
            files = set(fi for fi in files
                        if not fi.path.path.startswith(b'/lib'))
            return files, inputs, outputs
        finally:
            conn.close()

    @classmethod
    def make_paths(cls, obj):
        if isinstance(obj, set):
            return set(cls.make_paths(e) for e in obj)
        elif isinstance(obj, list):
            return [cls.make_paths(e) for e in obj]
        elif isinstance(obj, AbstractPath):
            return obj
        elif isinstance(obj, (bytes, unicode_)):
            return Path(obj)
        else:
            assert False

    def assertEqualPaths(self, objs, second):
        self.assertEqual(self.make_paths(objs), second)

    def test_get_files(self):
        files, inputs, outputs = self.do_test([
            ('proc', 0, None, False),
            ('open', 0, "/some/dir", True, FILE_WDIR),
            ('exec', 0, "/some/dir/ls", "/some/dir", "ls\0"),
            ('open', 0, "/some/otherdir/in", False, FILE_READ),
            ('open', 0, "/some/thing/created", True, FILE_WRITE),
            ('proc', 1, 0, False),
            ('open', 1, "/some/thing/created/file", False, FILE_WRITE),
            ('open', 1, "/some/thing/created/file", False, FILE_READ),
            ('open', 1, "/some/thing/created", True, FILE_WDIR),
            ('exec', 0, "/some/thing/created/file", "/some/thing/created",
             "created\0"),
        ])
        expected = set([
            '/some/dir',
            '/some/dir/ls',
            '/some/otherdir/in',
            '/some/thing',
        ])
        self.assertEqualPaths(expected,
                              set(fi.path for fi in files))

    def test_multiple_runs(self):
        def fail(s):
            assert False, "Shouldn't be called?"
        old = Path.is_file, Path.stat
        Path.is_file = lambda s: True
        Path.stat = fail
        try:
            files, inputs, outputs = self.do_test([
                ('proc', 0, None, False),
                ('open', 0, "/some/dir", True, FILE_WDIR),
                ('exec', 0, "/some/dir/ls", "/some/dir", b'ls\0/some/cli\0'),
                ('open', 0, "/some/cli", False, FILE_WRITE),
                ('open', 0, "/some/r", False, FILE_READ),
                ('open', 0, "/some/rw", False, FILE_READ),
                ('proc', 1, None, False),
                ('open', 1, "/some/dir", True, FILE_WDIR),
                ('exec', 1, "/some/dir/ls", "/some/dir", b'ls\0'),
                ('open', 1, "/some/cli", False, FILE_READ),
                ('proc', 2, 1, True),
                ('open', 2, "/some/r", False, FILE_READ),
                ('open', 1, "/some/rw", False, FILE_WRITE),
            ])
            expected = set([
                '/some',
                '/some/dir',
                '/some/dir/ls',
                '/some/r',
                '/some/rw',
            ])
            self.assertEqualPaths(expected,
                                  set(fi.path for fi in files))
            self.assertEqualPaths([set(["/some/r", "/some/rw"]),
                                   set(["/some/cli", "/some/r"])],
                                  [set(l) for l in inputs])
            self.assertEqualPaths([set(["/some/cli"]), set(["/some/rw"])],
                                  [set(l) for l in outputs])
        finally:
            Path.is_file, Path.stat = old
