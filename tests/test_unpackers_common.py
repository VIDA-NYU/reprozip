# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import sys
import unittest

from reprounzip.unpackers.common import UsageError, \
    unique_names, make_unique_name, get_runs
from reprounzip.utils import irange


class TestCommon(unittest.TestCase):
    def test_unique_names(self):
        """Tests the unique_names generator."""
        names = [next(unique_names) for i in irange(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes))
        self.assertEqual(len(set(names)), len(names))

    def test_make_unique_name(self):
        """Tests the make_unique_name() function."""
        names = [make_unique_name(b'/some/prefix_') for i in irange(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes) and
                            n[:13] == b'/some/prefix_')
        self.assertEqual(len(set(names)), len(names))


class TestMisc(unittest.TestCase):
    def do_ok(self, arg, expected, nruns=4):
        try:
            config_runs = [{'id': 'one'}, {'id': 'two-heh'},
                           {'id': 'three'}, {}]
            runs = get_runs(
                config_runs[:nruns],
                arg, None)
        except (SystemExit, UsageError):
            self.fail("get_runs(<4 runs>, %r) raised" % arg)
        self.assertEqual(list(runs), expected)

    def do_fail(self, arg):
        self.assertRaises((SystemExit, UsageError),
                          get_runs, [{}, {}, {}, {}], arg, None)

    def test_get_runs(self):
        """Tests get_runs(), parsing runs from the command-line."""
        print("<<<<< get_runs tests for reprounzip (disregard parse errors)",
              file=sys.stderr)
        try:
            self.do_fail('')
            self.do_fail('a-')
            self.do_fail('1-k')
            self.do_ok(None, [0, 1, 2, 3])
            self.do_ok('-', [0, 1, 2, 3])
            self.do_ok(None, [0], nruns=1)
            self.do_ok('-', [0], nruns=1)
            self.do_ok('1-', [1, 2, 3])
            self.do_ok('-2', [0, 1, 2])
            self.do_ok('1-2', [1, 2])
            self.do_ok('0-2', [0, 1, 2])
            self.do_ok('1-3', [1, 2, 3])
            self.do_ok('1-1', [1])
            self.do_fail('2-1')
            self.do_fail('0-8')
            self.do_fail('0-4')
            self.do_ok('0-3', [0, 1, 2, 3])
            self.do_ok('one', [0])
            self.do_ok('two-heh', [1]),
            self.do_ok('one,three', [0, 2])
            self.do_ok('1,three', [1, 2])
            self.do_ok('2-3,two-heh', [2, 3, 1])
        finally:
            print(">>>>> get_runs tests", file=sys.stderr)
