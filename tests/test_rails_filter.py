# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from reprozip.common import File
from reprozip.filters import ruby
from rpaths import Path
import unittest


class MockTracedFile(File):
    def __init__(self, path):
        File.__init__(self, path, None)


class RailsFilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path.tempdir(prefix='reprozip_tests_')

    def tearDown(self):
        self.tmp.rmtree()

    @classmethod
    def touch(cls, test_files):
        for fi in test_files:
            if not fi.parent.is_dir():
                fi.parent.mkdir(parents=True)
            with fi.open('a'):
                pass

    def test_consuming_entire_gem(self):
        gemdir = self.tmp / 'gems/ruby-2.2.3/gems/kaminari-0.16.3'
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

        self.touch(gemdir / f for f in gemfiles)

        input_files = [[]]
        files = {}

        for path in gemdir.recursedir():
            if b'_first' in path.name:
                f = MockTracedFile(path)
                files[f.path] = f
                input_files[0].append(path)

        ruby(files=files, input_files=input_files)

        self.assertEqual(set(files.keys()), set(gemdir / f for f in gemfiles))

    def test_consuming_rails_files(self):
        # Should be recognized: has a config file
        railsfiles = [
            'yes/config/application.rb',
            'yes/app/views/application.html.erb',
            'yes/app/views/discussion-sidebar.html.erb',
            'yes/app/views/payments_listing.html.erb',
            'yes/app/views/print-friendly.html.erb',
            'yes/app/views/w-sidebar.html.erb',
            'yes/app/views/widget.html.erb',
        ]
        # Should NOT be: no config file
        notrailsfiles = [
            # 'no/config/application.rb',
            'no/app/views/application.html.erb',
            'no/app/views/discussion-sidebar.html.erb',
            'no/app/views/payments_listing.html.erb',
            'no/app/views/print-friendly.html.erb',
            'no/app/views/w-sidebar.html.erb',
            'no/app/views/widget.html.erb',
        ]

        self.touch(self.tmp / f for f in railsfiles)
        self.touch(self.tmp / f for f in notrailsfiles)

        input_files = [[]]
        files = {}

        viewsdir = MockTracedFile(self.tmp / railsfiles[-1])
        files[viewsdir.path] = viewsdir
        viewsdir = MockTracedFile(self.tmp / notrailsfiles[-1])
        files[viewsdir.path] = viewsdir

        ruby(files, input_files)

        self.assertEqual(
            set(files.keys()),
            set(self.tmp / f for f in railsfiles + [notrailsfiles[-1]]),
        )
