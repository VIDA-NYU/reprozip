# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import os
import unittest
import tempfile
import shutil
from rpaths import Path
# from reprozip.tracer.trace import TracedFile
from reprozip.common import File
from reprozip.filters import ruby


class MockTracedFile(File):

    def __init(self, path):
        File.__init(self, path, None)


class RailsFilterTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp('reprozip-tests'))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls.tmp))

    @classmethod
    def touch(cls, test_files):
        for fi in test_files:
            if not fi.parent.is_dir():
                fi.parent.mkdir(parents=True)
            with open(str(fi), 'a'):
                os.utime(str(fi), None)

    def test_consuming_entire_gem(self):
        gemdir = self.__class__.tmp / \
            'gems/ruby-2.2.3/gems/kaminari-0.16.3'
        gemfiles = [
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

        self.__class__.touch(
            map(lambda f: gemdir / f, gemfiles))

        input_files = {}
        files = {}

        for path in gemdir.recursedir():
            if not path.name.find(b'_first'):
                f = MockTracedFile(path)
                files[f.path] = f

        ruby(files, input_files)

        for gf in gemfiles:
            gfp = gemdir / gf
            self.assertIn(gfp, files.keys())
            self.assertEqual(gfp, files[gfp].path)

        # sometimes it's a little different path
        gemdir = self.__class__.tmp / 'gems/ruby/2.1.0/gems/kaminari-0.16.3'

        self.__class__.touch(
            map(lambda f: gemdir / f, gemfiles))

        input_files = {}
        files = {}

        for path in gemdir.recursedir():
            if not path.name.find(b'_first'):
                f = MockTracedFile(path)
                files[f.path] = f

        ruby(files, input_files)

        for gf in gemfiles:
            gfp = gemdir / gf
            self.assertIn(gfp, files.keys())
            self.assertEqual(gfp, files[gfp].path)

    def test_consuming_rails_files(self):
        railsdir = self.__class__.tmp / 'rails-app'
        railsfiles = [
            'config/application.rb',
            'app/views/application.html.erb',
            'app/views/discussion-sidebar.html.erb',
            'app/views/payments_listing.html.erb',
            'app/views/print-friendly.html.erb',
            'app/views/w-sidebar.html.erb',
            'app/views/widget.html.erb']

        self.__class__.touch(
            map(lambda f: railsdir / f, railsfiles))

        input_files = {}
        files = {}

        viewsdir = MockTracedFile(railsdir / 'app/views')
        files[viewsdir.path] = viewsdir

        ruby(files, input_files)

        for fi in railsfiles[1:]:
            fp = railsdir / fi
            self.assertIn(fp, files.keys())
            self.assertEqual(fp, files[fp].path)

        norailsdir = self.__class__.tmp / 'no-rails-app'
        norailsfiles = [
            # 'config/application.rb',
            'app/views/application.html.erb',
            'app/views/discussion-sidebar.html.erb',
            'app/views/payments_listing.html.erb',
            'app/views/print-friendly.html.erb',
            'app/views/w-sidebar.html.erb',
            'app/views/widget.html.erb']

        self.__class__.touch(
            map(lambda f: norailsdir / f, norailsfiles))

        input_files = {}
        files = {}

        viewsdir = MockTracedFile(norailsdir / 'app/views')
        files[viewsdir.path] = viewsdir

        ruby(files, input_files)

        for fi in norailsfiles:
            fp = norailsdir / fi
            self.assertNotIn(fp, files.keys())
