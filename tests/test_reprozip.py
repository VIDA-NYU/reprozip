# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import os
from rpaths import Path
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
