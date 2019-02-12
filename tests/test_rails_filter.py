# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import os
import unittest
import tempfile
from rpaths import Path
# from reprozip.tracer.trace import TracedFile
from reprozip.common import File
from reprozip.filters import ruby_gems


class MockTracedFile(File):

    def __init(self, path):
        File.__init(self, path, None)


class RailsFilterTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.gemdir = Path(tempfile.mkdtemp('reprozip-tests')) / \
            'gems/ruby-2.2.3/gems/kaminari-0.16.3'
        cls.gemfiles = [
            'app/views/kaminari/_first_page.html.erb',
            'app/views/kaminari/_first_page.html.haml',
            'app/views/kaminari/_first_page.html.slim',
            'app/views/kaminari/_gap.html.erb',
            'app/views/kaminari/_gap.html.haml',
            'app/views/kaminari/_gap.html.slim',
            'app/views/kaminari/_last_page.html.erb',
            'app/views/kaminari/_last_page.html.haml',
            'app/views/kaminari/_last_page.html.slim',
        ]

        for gf in cls.gemfiles:
            gfp = cls.gemdir / gf
            if not gfp.parent.is_dir():
                gfp.parent.mkdir(parents=True)
            # gfp.touch()
            with open(str(gfp), 'a'):
                os.utime(str(gfp), None)

    def test_consuming_entire_gem(self):
        input_files = {}
        files = {}

        for path in self.__class__.gemdir.recursedir():
            if not path.name.find(b'_first'):
                f = MockTracedFile(path)
                files[f.path] = f

        ruby_gems(files, input_files)

        for gf in self.__class__.gemfiles:
            gfp = self.__class__.gemdir / gf
            self.assertIn(gfp, files.keys())
            self.assertEqual(gfp, files[gfp].path)
