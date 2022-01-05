# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import os
import sys
import unittest

from reprounzip.unpackers.common import UsageError, \
    unique_names, make_unique_name, get_runs, parse_environment_args, \
    fixup_environment


class TestCommon(unittest.TestCase):
    def test_unique_names(self):
        """Tests the unique_names generator."""
        names = [next(unique_names) for i in range(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes))
        self.assertEqual(len(set(names)), len(names))

    def test_make_unique_name(self):
        """Tests the make_unique_name() function."""
        names = [make_unique_name(b'some_prefix_') for i in range(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes) and
                            n[:12] == b'some_prefix_')
        self.assertEqual(len(set(names)), len(names))

    def test_env(self):
        """Tests fixing environment variables"""
        outer_env = {
            'OUTONLY': 'outvalue',
            'COMMON': 'commonvalueout',
            'SHARED': 'sharedvalue',
            'EMPTY': '',
        }
        inner_env = {
            'INONLY': 'invalue',
            'COMMON': 'commonvaluein',
            'SHARED': 'sharedvalue',
        }

        class FakeArgs(object):
            def __init__(self, pass_env, set_env):
                self.pass_env = pass_env
                self.set_env = set_env

        old_environ, os.environ = os.environ, outer_env
        try:
            self.assertEqual(
                parse_environment_args(
                    FakeArgs([], [])),
                ({}, []))
            self.assertEqual(
                fixup_environment(
                    inner_env,
                    FakeArgs([], [])),
                {
                    'INONLY': 'invalue',
                    'COMMON': 'commonvaluein',
                    'SHARED': 'sharedvalue',
                })

            self.assertEqual(
                parse_environment_args(
                    FakeArgs(['COMMON', 'INONLY', 'OUTONLY', 'EMPTY'], [])),
                ({'OUTONLY': 'outvalue',
                  'COMMON': 'commonvalueout',
                  'EMPTY': ''},
                 []))
            self.assertEqual(
                fixup_environment(
                    inner_env,
                    FakeArgs(['COMMON', 'INONLY', 'OUTONLY', 'EMPTY'], [])),
                {
                    'INONLY': 'invalue',
                    'OUTONLY': 'outvalue',
                    'COMMON': 'commonvalueout',
                    'SHARED': 'sharedvalue',
                    'EMPTY': '',
                })

            self.assertEqual(
                parse_environment_args(
                    FakeArgs(['OUTONLY'],
                             ['SHARED=surprise', 'COMMON=', 'INONLY'])),
                ({'OUTONLY': 'outvalue',
                  'COMMON': '',
                  'SHARED': 'surprise'},
                 ['INONLY']))
            self.assertEqual(
                fixup_environment(
                    inner_env,
                    FakeArgs(['OUTONLY'],
                             ['SHARED=surprise', 'COMMON=', 'INONLY'])),
                {
                    'OUTONLY': 'outvalue',
                    'COMMON': '',
                    'SHARED': 'surprise',
                })

            self.assertEqual(
                parse_environment_args(
                    FakeArgs(['.*Y$'], [])),
                ({'OUTONLY': 'outvalue', 'EMPTY': ''}, []))
            self.assertEqual(
                fixup_environment(
                    inner_env,
                    FakeArgs(['.*Y$'], [])),
                {
                    'INONLY': 'invalue',
                    'OUTONLY': 'outvalue',
                    'COMMON': 'commonvaluein',
                    'SHARED': 'sharedvalue',
                    'EMPTY': '',
                })
        finally:
            os.environ = old_environ


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
