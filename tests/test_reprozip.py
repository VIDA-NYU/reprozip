# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import os
from pathlib import Path, PurePath, PurePosixPath
import sqlite3
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from reprozip_core.common import FILE_READ, FILE_WRITE, FILE_WDIR, File, \
    Package, InputOutputFile, create_trace_schema, load_config
from reprozip.tracer.trace import TracedFile, get_files, compile_inputs_outputs
from reprozip import traceutils
from reprozip_core.utils import UniqueNames, make_dir_writable

from tests.common import make_database


class TestReprozip(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'chown'), "No POSIX file permissions")
    def test_make_dir_writable(self):
        """Tests make_dir_writable with read-only dir."""
        def check_mode(mod, path):
            self.assertEqual(oct((path.stat().st_mode & 0o0700) >> 6),
                             oct(mod))

        tmp = Path(tempfile.mkdtemp())
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
            shutil.rmtree(tmp)

    @unittest.skipUnless(hasattr(os, 'chown'), "No POSIX file permissions")
    def test_make_dir_writable2(self):
        """Tests make_dir_writable with read-only and no-executable dirs."""
        def check_mode(mod, path):
            self.assertEqual(oct((path.stat().st_mode & 0o0700) >> 6),
                             oct(mod))

        tmp = Path(tempfile.mkdtemp())
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
            shutil.rmtree(tmp)

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
                    reprozip.main.main()
                self.assertEqual(cm.exception.code, c)
                if c == 0:
                    self.assertEqual(calls, [('l', v), ('t', v)])
                calls = []
        finally:
            print(">>>>> argparse tests", file=sys.stderr)
            sys.argv = old_argv
            reprozip.main.testrun, reprozip.main.setup_logging = old_funcs


class TestConfig(unittest.TestCase):
    def load_config(self, name, canonical):
        path = Path(__file__).parent / 'configs' / name
        config = load_config(path, canonical)
        keys = {k for k in dir(config) if not k.startswith('_')}
        keys -= {'count', 'index'}  # tuple methods
        if canonical:
            self.assertEqual(keys, {
                'format_version', 'runs', 'inputs_outputs',
                'packages', 'other_files',
            })
        else:
            self.assertEqual(keys, {
                'format_version', 'runs', 'inputs_outputs',
                'packages', 'other_files',
                'additional_patterns',
            })
        return config

    def test_load_0_4_1(self):
        config = self.load_config('config-0.4.1-edit.yml', False)
        self.assertEqual(config.format_version, '0.4.1')
        self.assertEqual(config.runs, [
            {
                'architecture': 'x86_64',
                'argv': ['sh', '-c', 'wc -l /tmp/input.txt >/tmp/lines'],
                'binary': '/bin/sh',
                'distribution': ['Ubuntu', '20.04'],
                'environ': {'HOME': '/home/remram', 'LANG': 'en_US.UTF-8'},
                'exitcode': 0,
                'gid': 1000,
                'hostname': 'axon',
                'id': 'run0',
                'system': ['Linux', '5.4.0-80-generic'],
                'uid': 1000,
                'workingdir': '/home/remram',
            }
        ])
        self.assertEqual(config.inputs_outputs, {
            'text': InputOutputFile(PurePosixPath('/tmp/input.txt'), [0], []),
            'lines': InputOutputFile(PurePosixPath('/tmp/lines'), [], [0]),
        })
        self.assertEqual(config.packages, [
            Package('coreutils', '8.30-3ubuntu2'),
            Package('libc6', '2.31-0ubuntu9.3'),
        ])
        self.assertEqual(config.packages[0].files, [
            File(PurePosixPath('/usr/bin/wc')),
        ])
        self.assertEqual(config.packages[1].files, [
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc-2.31.so')),
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc.so.6')),
        ])
        self.assertEqual(config.other_files, [
            File(PurePosixPath('/tmp')),
            File(PurePosixPath('/tmp/input.txt')),
            File(PurePosixPath('/usr/lib/locale/locale-archive')),
        ])
        self.assertEqual(config.additional_patterns, ['/etc/apache2/**'])

        config = self.load_config('config-0.4.1-packed.yml', True)
        self.assertEqual(config.format_version, '0.4.1')
        self.assertEqual(config.runs, [
            {
                'architecture': 'x86_64',
                'argv': ['sh', '-c', 'wc -l /tmp/input.txt >/tmp/lines'],
                'binary': '/bin/sh',
                'distribution': ['Ubuntu', '20.04'],
                'environ': {'HOME': '/home/remram', 'LANG': 'en_US.UTF-8'},
                'exitcode': 0,
                'gid': 1000,
                'hostname': 'axon',
                'id': 'run0',
                'system': ['Linux', '5.4.0-80-generic'],
                'uid': 1000,
                'workingdir': '/home/remram',
            }
        ])
        self.assertEqual(config.inputs_outputs, {
            'text': InputOutputFile(PurePosixPath('/tmp/input.txt'), [0], []),
            'lines': InputOutputFile(PurePosixPath('/tmp/lines'), [], [0]),
        })
        self.assertEqual(config.packages, [
            Package('coreutils', '8.30-3ubuntu2'),
            Package('libc6', '2.31-0ubuntu9.3'),
        ])
        self.assertEqual(config.packages[0].files, [
            File(PurePosixPath('/usr/bin/wc')),
        ])
        self.assertEqual(config.packages[1].files, [
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc-2.31.so')),
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc.so.6')),
        ])
        self.assertEqual(config.other_files, [
            File(PurePosixPath('/tmp')),
            File(PurePosixPath('/tmp/input.txt')),
            File(PurePosixPath('/usr/lib/locale/locale-archive')),
        ])

    def test_load_0_8(self):
        config = self.load_config('config-1.0-edit.yml', False)
        self.assertEqual(config.format_version, '0.8')
        self.assertEqual(config.runs, [
            {
                'architecture': 'x86_64',
                'argv': ['sh', '-c', 'wc -l /tmp/input.txt >/tmp/lines'],
                'binary': '/bin/sh',
                'distribution': ['ubuntu', '20.04'],
                'environ': {'HOME': '/home/remram', 'LANG': 'en_US.UTF-8'},
                'exitcode': 0,
                'gid': 1000,
                'hostname': 'axon',
                'id': 'run0',
                'system': ['Linux', '5.4.0-80-generic'],
                'uid': 1000,
                'workingdir': '/home/remram',
            }
        ])
        self.assertEqual(config.inputs_outputs, {
            'text': InputOutputFile(PurePosixPath('/tmp/input.txt'), [0], []),
            'lines': InputOutputFile(PurePosixPath('/tmp/lines'), [], [0]),
            'other': InputOutputFile(PurePosixPath('/tmp/other'), [0], [0]),
        })
        self.assertEqual(config.packages, [
            Package('coreutils', '8.30-3ubuntu2'),
            Package('libc6', '2.31-0ubuntu9.3'),
        ])
        self.assertEqual(config.packages[0].files, [
            File(PurePosixPath('/usr/bin/wc')),
        ])
        self.assertEqual(config.packages[1].files, [
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc-2.31.so')),
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc.so.6')),
        ])
        self.assertEqual(config.other_files, [
            File(PurePosixPath('/tmp')),
            File(PurePosixPath('/tmp/input.txt')),
            File(PurePosixPath('/usr/lib/locale/locale-archive')),
        ])
        self.assertEqual(config.additional_patterns, ['/etc/apache2/**'])

        config = self.load_config('config-1.0-packed.yml', True)
        self.assertEqual(config.format_version, '0.8')
        self.assertEqual(config.runs, [
            {
                'architecture': 'x86_64',
                'argv': ['sh', '-c', 'wc -l /tmp/input.txt >/tmp/lines'],
                'binary': '/bin/sh',
                'distribution': ['ubuntu', '20.04'],
                'environ': {'HOME': '/home/remram', 'LANG': 'en_US.UTF-8'},
                'exitcode': 0,
                'gid': 1000,
                'hostname': 'axon',
                'id': 'run0',
                'system': ['Linux', '5.4.0-80-generic'],
                'uid': 1000,
                'workingdir': '/home/remram',
            }
        ])
        self.assertEqual(config.inputs_outputs, {
            'text': InputOutputFile(PurePosixPath('/tmp/input.txt'), [0], []),
            'lines': InputOutputFile(PurePosixPath('/tmp/lines'), [], [0]),
            'other': InputOutputFile(PurePosixPath('/tmp/other'), [0], [0]),
        })
        self.assertEqual(config.packages, [
            Package('coreutils', '8.30-3ubuntu2'),
            Package('libc6', '2.31-0ubuntu9.3'),
        ])
        self.assertEqual(config.packages[0].files, [
            File(PurePosixPath('/usr/bin/wc')),
        ])
        self.assertEqual(config.packages[1].files, [
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc-2.31.so')),
            File(PurePosixPath('/lib/x86_64-linux-gnu/libc.so.6')),
        ])
        self.assertEqual(config.other_files, [
            File(PurePosixPath('/tmp')),
            File(PurePosixPath('/tmp/input.txt')),
            File(PurePosixPath('/usr/lib/locale/locale-archive')),
        ])


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
                        if not str(fi.path).startswith(('/lib', '/usr/lib')))
            return files, inputs, outputs
        finally:
            conn.close()

    @classmethod
    def make_paths(cls, obj):
        if isinstance(obj, set):
            return set(cls.make_paths(e) for e in obj)
        elif isinstance(obj, list):
            return [cls.make_paths(e) for e in obj]
        elif isinstance(obj, PurePath):
            return obj
        elif isinstance(obj, (bytes, str)):
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
        expected = {
            '/some/dir',
            '/some/dir/ls',
            '/some/otherdir/in',
            '/some/thing',
        }
        self.assertEqualPaths(expected,
                              set(fi.path for fi in files))

    def test_multiple_runs(self):
        # Input/output determination will stat files, so mock that
        file_stat = Path('/etc/passwd').stat()
        old = Path.is_file, Path.exists, Path.stat
        Path.is_file = Path.exists = lambda s: True
        Path.stat = lambda s, *, follow_symlinks=True: file_stat
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
            expected = {
                '/some',
                '/some/dir',
                '/some/dir/ls',
                '/some/r',
                '/some/rw',
            }
            self.assertEqualPaths(expected,
                                  set(fi.path for fi in files))
            self.assertEqualPaths([{"/some/r", "/some/rw"},
                                   {"/some/cli", "/some/r"}],
                                  [set(run) for run in inputs])
            self.assertEqualPaths([{"/some/cli"}, {"/some/rw"}],
                                  [set(run) for run in outputs])
        finally:
            Path.is_file, Path.exists, Path.stat = old


class TestCombine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_combine_traces(self):
        traces = []
        sql_data = [
            '''
INSERT INTO "processes" VALUES(1,0,NULL,12345678901001,12345678901002,5,0,0);
INSERT INTO "opened_files" VALUES(1,0,'/home/vagrant',12345678901001,4,1,1);
INSERT INTO "opened_files" VALUES(2,0,'/lib/ld.so',12345678901003,1,0,1);
INSERT INTO "executed_files" VALUES(1,'/usr/bin/id',0,12345678901002,1,'id',
    'RUN=first','/home/vagrant');
INSERT INTO "connections" VALUES(1,0,12345678901001,1,0,"INET","UDP",
    "127.0.0.1:53");
            ''',
            '''
INSERT INTO "processes" VALUES(1,0,NULL,12345678902001,12345678902003,6,0,0);
INSERT INTO "processes" VALUES(2,0,1,12345678902002,12345678902004,7,1,0);
INSERT INTO "processes" VALUES(3,1,NULL,12345678902004,12345678902005,8,0,0);
INSERT INTO "processes" VALUES(4,1,3,12345678902005,12345678902006,9,0,1);
INSERT INTO "opened_files" VALUES(1,0,'/usr',12345678902001,4,1,1);
INSERT INTO "opened_files" VALUES(2,0,'/lib/ld.so',12345678902003,1,0,2);
INSERT INTO "opened_files" VALUES(3,1,'/usr/bin',12345678902004,4,1,3);
INSERT INTO "executed_files" VALUES(1,'/usr/bin/id',1,12345678902006,4,'id',
    'RUN=third','/home/vagrant');
INSERT INTO "connections" VALUES(1,0,12345678902001,1,0,"INET","UDP",
    "127.0.0.2:53");
INSERT INTO "connections" VALUES(2,1,12345678902005,4,0,"INET6","TCP",
    "127.0.0.3:80");
            ''',
            '''
INSERT INTO "processes" VALUES(0,0,NULL,12345678903001,12345678903002,4,0,1);
INSERT INTO "opened_files" VALUES(0,0,'/home',12345678903001,4,1,0);
INSERT INTO "executed_files" VALUES(1,'/bin/false',0,12345678903002,0,'false',
    'RUN=fourth','/home');
INSERT INTO "connections" VALUES(0,0,12345678903001,0,0,"INET","UDP",
    "127.0.0.1:53");
            ''']

        for i, dat in enumerate(sql_data):
            trace = self.tmpdir / ('trace%d.sqlite3' % i)
            conn = sqlite3.connect(str(trace))  # connect() only accepts str
            conn.row_factory = sqlite3.Row
            create_trace_schema(conn)
            conn.executescript('PRAGMA foreign_keys=OFF; BEGIN TRANSACTION;' +
                               dat +
                               'COMMIT;')
            conn.commit()
            conn.close()

            traces.append(trace)

        target = self.tmpdir / 'target'
        traceutils.combine_traces(traces, target)
        target = target / 'trace.sqlite3'

        conn = sqlite3.connect(str(target))  # connect() only accepts str
        conn.row_factory = None
        processes = list(conn.execute(
            '''
            SELECT * FROM processes;
            '''))
        opened_files = list(conn.execute(
            '''
            SELECT * FROM opened_files;
            '''))
        executed_files = list(conn.execute(
            '''
            SELECT * FROM executed_files;
            '''))
        connections = list(conn.execute(
            '''
            SELECT * FROM connections;
            '''))

        self.assertEqual([processes, opened_files, executed_files,
                          connections], [
            [(1, 1, None, 12345678901001, 12345678901002, 5, 0, 0),
             (2, 2, None, 12345678902001, 12345678902003, 6, 0, 0),
             (3, 2, 1, 12345678902002, 12345678902004, 7, 1, 0),
             (4, 3, None, 12345678902004, 12345678902005, 8, 0, 0),
             (5, 3, 3, 12345678902005, 12345678902006, 9, 0, 1),
             (6, 4, None, 12345678903001, 12345678903002, 4, 0, 1)],

            [(1, 1, '/home/vagrant', 12345678901001, 4, 1, 1),
             (2, 1, '/lib/ld.so', 12345678901003, 1, 0, 1),
             (3, 2, '/usr', 12345678902001, 4, 1, 2),
             (4, 2, '/lib/ld.so', 12345678902003, 1, 0, 3),
             (5, 3, '/usr/bin', 12345678902004, 4, 1, 4),
             (6, 4, '/home', 12345678903001, 4, 1, 6)],

            [(1, '/usr/bin/id', 1, 12345678901002, 1, 'id',
              'RUN=first', '/home/vagrant'),
             (2, '/usr/bin/id', 3, 12345678902006, 5, 'id',
              'RUN=third', '/home/vagrant'),
             (3, '/bin/false', 4, 12345678903002, 6, 'false',
              'RUN=fourth', '/home')],

            [(1, 1, 12345678901001, 1, 0, 'INET', 'UDP', '127.0.0.1:53'),
             (2, 2, 12345678902001, 2, 0, 'INET', 'UDP', '127.0.0.2:53'),
             (3, 3, 12345678902005, 5, 0, 'INET6', 'TCP', '127.0.0.3:80'),
             (4, 4, 12345678903001, 6, 0, 'INET', 'UDP', '127.0.0.1:53')],
        ])

    def test_combine_files(self):
        # Patch TracedObject constructor to not go to disk to read size etc
        def _mock_TracedObject_init(self, path):
            super(TracedFile, self).__init__(path, None)

        with mock.patch.object(
            TracedFile, '__init__',
            _mock_TracedObject_init,
        ):
            # Call combine_files()
            files, packages = traceutils.combine_files(
                [File('/tmp/a'), File('/tmp/c')],
                [
                    Package('pkg1', '1.0.0', [File('/usr/a'), File('/usr/c')]),
                    Package('pkg2', '2.0.0', [File('/usr/d'), File('/usr/e')]),
                ],
                [File('/tmp/a'), File('/tmp/b')],
                [
                    Package('pkg1', '1.0.0', [File('/usr/a'), File('/usr/b')]),
                    Package('pkg3', '3.0.0', [File('/usr/f'), File('/usr/g')]),
                ],
            )
        self.assertEqual(
            files,
            {File('/tmp/a'), File('/tmp/b'), File('/tmp/c')},
        )
        self.assertEqual(
            sorted(packages, key=lambda pkg: pkg.name),
            [
                Package('pkg1', '1.0.0'),
                Package('pkg2', '2.0.0'),
                Package('pkg3', '3.0.0'),
            ],
        )
        packages = {pkg.name: pkg for pkg in packages}
        self.assertEqual(set(packages['pkg1'].files), {
            File('/usr/a'), File('/usr/b'), File('/usr/c'),
        })
        self.assertEqual(set(packages['pkg2'].files), {
            File('/usr/d'), File('/usr/e'),
        })
        self.assertEqual(set(packages['pkg3'].files), {
            File('/usr/f'), File('/usr/g'),
        })
