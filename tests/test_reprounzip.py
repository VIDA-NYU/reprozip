# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import io
import os
import sys
import tarfile
import tempfile
import unittest
import warnings

from reprounzip.common import RPZPack
from reprounzip.signals import Signal


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
    def test_rpzpack(self):
        def write_to_tar(tar, path, data, **kwargs):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            for key, value in kwargs.items():
                if not hasattr(info, key):
                    raise AttributeError(key)
                setattr(info, key, value)
            tar.addfile(info, io.BytesIO(data))

        with tempfile.TemporaryDirectory() as tmp:
            # Create data tar.gz
            data = os.path.join(tmp, 'DATA.tar.gz')
            tar = tarfile.open(data, 'w:gz')
            write_to_tar(
                tar,
                'DATA/bin/init',
                b'#!/bin/sh\necho "Success."\n',
                mode=0o755,
            )

            # Create rpz
            rpz = os.path.join(tmp, 'test.rpz')
            tar = tarfile.open(rpz, 'w:')
            write_to_tar(
                tar,
                'METADATA/version',
                b'REPROZIP VERSION 2\n',
            )
            write_to_tar(
                tar,
                'METADATA/trace.sqlite3',
                b'',
            )
            write_to_tar(
                tar,
                'METADATA/config.yml',
                b'{}',
            )
            tar.add(
                data,
                'DATA.tar.gz',
            )

            # Add directory extension
            write_to_tar(
                tar,
                'EXTENSIONS/foo/one.txt',
                b'',
            )
            write_to_tar(
                tar,
                'EXTENSIONS/foo/two.txt',
                b'',
            )

            # Add single file extension
            write_to_tar(
                tar,
                'EXTENSIONS/bar',
                b'',
            )

            tar.close()

            rpz_obj = RPZPack(rpz)
            with rpz_obj.open_config() as fp:
                self.assertEqual(fp.read(), b'{}')
            self.assertEqual(rpz_obj.extensions(), {'foo', 'bar'})
