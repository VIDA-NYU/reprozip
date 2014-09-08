import os
from rpaths import Path
import unittest

from reprozip.utils import make_dir_writable


class TestReprozip(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'chown'), "No POSIX file permissions")
    def test_make_dir_writable(self):
        """Tests make_dir_writable with read-only dir."""
        def check_mode(mod, path):
            self.assertEqual(path.stat().st_mode & 0o7777, mod)

        tmp = Path.tempdir()
        try:
            (tmp / 'some' / 'path').mkdir(parents=True)
            (tmp / 'some' / 'path').chmod(0o555)
            with make_dir_writable(tmp / 'some' / 'path'):
                check_mode(0o755, tmp / 'some')
                check_mode(0o755, tmp / 'some' / 'path')
            check_mode(0o755, tmp / 'some')
            check_mode(0o555, tmp / 'some' / 'path')
        finally:
            (tmp / 'some').chmod(0o755)
            (tmp / 'some' / 'path').chmod(0o755)
            tmp.rmtree()
