# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import os
from rpaths import Path
import sys
import unittest

from reprozip.utils import make_dir_writable


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
            sys.argv = old_argv
            reprozip.main.testrun, reprozip.main.setup_logging = old_funcs
