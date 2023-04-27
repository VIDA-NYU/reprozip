# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.
import argparse
import contextlib
import logging
import os
import tempfile
import unittest

from reprozip_core.common import RPZPack
from reprozip_web.main import cmd_combine
from tests.common import capture_logs
from tests.test_reprounzip import TarBuilder, ZipBuilder


class TestCombine(unittest.TestCase):
    @contextlib.contextmanager
    def make_rpz(self, outer_container, ext):
        with tempfile.TemporaryDirectory() as tmp:
            # Create data tar.gz
            data = os.path.join(tmp, 'DATA.tar.gz')
            arc = TarBuilder(data, 'w:gz')
            arc.write_data(
                'DATA/bin/init',
                b'#!/bin/sh\necho "Success."\n',
                mode=0o755,
            )
            arc.close()

            # Create rpz
            rpz = os.path.join(tmp, 'test.rpz')
            arc = outer_container(rpz)
            arc.write_data(
                'METADATA/version',
                b'REPROZIP VERSION 2\n',
            )
            arc.write_data(
                'METADATA/trace.sqlite3',
                b'',
            )
            arc.write_data(
                'METADATA/config.yml',
                b'{}',
            )
            arc.add_file(
                data,
                'DATA.tar.gz',
            )

            # Add extension
            if ext is not None:
                arc.write_data(
                    'EXTENSIONS/%s/test.txt' % ext,
                    b'data',
                )

            arc.close()

            yield tmp

    def test_tar_add(self):
        with self.make_rpz(lambda p: TarBuilder(p, 'w:'), None) as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(logs, [])
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()

    def test_tar_replace(self):
        with self.make_rpz(lambda p: TarBuilder(p, 'w:'), 'web1') as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(
                [log.msg for log in logs],
                ['Replacing existing web extension from input RPZ'],
            )
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()

    def test_tar_replace_unknown(self):
        with self.make_rpz(lambda p: TarBuilder(p, 'w:'), 'webX') as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(
                [log.msg for log in logs],
                ['Replacing UNKNOWN web extension version from input RPZ'],
            )
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()

    def test_zip_add(self):
        with self.make_rpz(lambda p: ZipBuilder(p), None) as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(logs, [])
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()

    def test_zip_replace(self):
        with self.make_rpz(lambda p: ZipBuilder(p), 'web1') as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(
                [log.msg for log in logs],
                ['Replacing existing web extension from input RPZ'],
            )
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()

    def test_zip_replace_unknown(self):
        with self.make_rpz(lambda p: ZipBuilder(p), 'webX') as tmp:
            with open(os.path.join(tmp, 'test.wacz'), 'w') as fp:
                fp.write('test\n')
            with capture_logs(level=logging.WARNING) as logs:
                cmd_combine(argparse.Namespace(
                    input_rpz=os.path.join(tmp, 'test.rpz'),
                    input_wacz=os.path.join(tmp, 'test.wacz'),
                    output_rpz=None,
                ))
            self.assertEqual(
                [log.msg for log in logs],
                ['Replacing UNKNOWN web extension version from input RPZ'],
            )
            rpz = RPZPack(os.path.join(tmp, 'test.web.rpz'))
            self.assertEqual(rpz.extensions(), {'web1'})
            rpz.close()
