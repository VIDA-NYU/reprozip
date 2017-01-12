# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import os
import sys
import unittest
import warnings

from reprounzip.signals import Signal
import reprounzip.unpackers.common


class TestSignals(unittest.TestCase):
    def test_make_signal(self):
        """Tests signal creation."""
        Signal(['p1', 'p2'])

        sig = Signal(['p1'], new_args=['p3'], old_args=['p4'])
        self.assertEqual(sig._args,
                         {'p1': Signal.REQUIRED,
                          'p3': Signal.OPTIONAL,
                          'p4': Signal.DEPRECATED})

        with self.assertRaises(ValueError):
            Signal(['p1', 'p2'], new_args=['p2', 'p3'])

    def test_subscription(self):
        """Tests subscribe() and unsubscribe()."""
        def foo(info):
            pass

        sig = Signal()
        sig.subscribe(foo)
        with self.assertRaises(TypeError):
            sig.subscribe(object())
        with self.assertRaises(TypeError):
            sig.subscribe(2)
        sig.unsubscribe(4)
        self.assertEqual(sig._listeners, set([foo]))
        sig.unsubscribe(foo)
        self.assertFalse(sig._listeners)

    def test_calls(self):
        """Tests actually emitting signals."""
        def called(**kwargs):
            called.last = kwargs

        def callsig(res_type, **kwargs):
            if res_type not in ('succ', 'warn', 'fail'):
                raise TypeError
            called.last = None
            with warnings.catch_warnings(record=True) as w:
                warnings.resetwarnings()
                sig(**kwargs)
            if res_type == 'fail' or res_type == 'warn':
                self.assertEqual(len(w), 1)
            if res_type == 'succ' or res_type == 'warn':
                self.assertEqual(called.last, kwargs)

        sig = Signal(['a', 'b'], new_args=['c'], old_args=['d'])
        sig.subscribe(called)

        callsig('succ', a=1, b=2)
        callsig('succ', a=1, b=2, c=3)
        callsig('fail', a=1)
        callsig('warn', a=1, b=2, d=3)


class TestArgs(unittest.TestCase):
    def test_argparse(self):
        """Tests argument parsing"""
        calls = []

        def chroot_run(args):
            calls.append(('c', args.verbosity))

        def setup_logging(tag, verbosity):
            calls.append(('l', verbosity))

        import reprounzip.main
        import reprounzip.unpackers.default

        old_funcs = (reprounzip.unpackers.default.chroot_run,
                     reprounzip.main.setup_logging)
        reprounzip.unpackers.default.chroot_run = chroot_run
        reprounzip.main.setup_logging = setup_logging
        old_argv = sys.argv
        print("<<<<< argparse tests for reprounzip (disregard usage warnings)",
              file=sys.stderr)
        try:
            for a, c, v in [('reprounzip', 2, -1),
                            ('reprounzip -v', 2, -1),
                            ('reprounzip chroot run a', 0, 1),
                            ('reprounzip chroot -v run a', 2, -1),
                            ('reprounzip -v chroot run a', 0, 2),
                            ('reprounzip -v -v chroot run a', 0, 3),
                            ('reprounzip chroot run -v a', 2, -1)]:
                sys.argv = a.split()
                with self.assertRaises(SystemExit) as cm:
                    reprounzip.main.main()
                self.assertEqual(cm.exception.code, c)
                if c == 0:
                    self.assertEqual(calls, [('l', v), ('c', v)])
                calls = []
        finally:
            print(">>>>> argparse tests", file=sys.stderr)
            sys.argv = old_argv
        (reprounzip.unpackers.default.chroot_run,
         reprounzip.main.setup_logging) = old_funcs


class TestCommon(unittest.TestCase):
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
                reprounzip.unpackers.common.fixup_environment(
                    inner_env,
                    FakeArgs([], [])),
                {
                    'INONLY': 'invalue',
                    'COMMON': 'commonvaluein',
                    'SHARED': 'sharedvalue',
                })

            self.assertEqual(
                reprounzip.unpackers.common.fixup_environment(
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
                reprounzip.unpackers.common.fixup_environment(
                    inner_env,
                    FakeArgs(['OUTONLY'],
                             ['SHARED=surprise', 'COMMON=', 'INONLY'])),
                {
                    'OUTONLY': 'outvalue',
                    'COMMON': '',
                    'SHARED': 'surprise',
                })

            self.assertEqual(
                reprounzip.unpackers.common.fixup_environment(
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
