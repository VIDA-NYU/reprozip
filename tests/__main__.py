# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import argparse
import locale
import logging
import os
import sys
import unittest
import warnings


top_level = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
start_dir = os.path.join(top_level, 'tests')
if top_level not in sys.path:
    sys.path.insert(0, top_level)


sys.path.append(start_dir)


from reprounzip.common import setup_logging     # noqa
from reprounzip.signals import SignalWarning    # noqa

from tests.functional import functional_tests   # noqa


class Program(unittest.TestProgram):
    def createTests(self):
        if self.testNames is None:
            self.test = self.testLoader.discover(
                start_dir=os.path.dirname(os.path.abspath(__file__)),
                pattern='test_*.py')
        else:
            self.test = self.testLoader.loadTestsFromNames(self.testNames)


if __name__ == '__main__':
    # Locale
    locale.setlocale(locale.LC_ALL, '')

    # Disables usage reporting
    os.environ['REPROZIP_USAGE_STATS'] = 'off'

    setup_logging('TESTSUITE', 999)

    parser = argparse.ArgumentParser(description="reprozip tests")
    parser.add_argument('--unittests', action='store_true',
                        dest='unittests', default=None)
    parser.add_argument('--no-unittests', action='store_false',
                        dest='unittests', default=None)
    parser.add_argument('--functests', action='store_true',
                        dest='functests', default=None)
    parser.add_argument('--no-functests', action='store_false',
                        dest='functests', default=None)
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--run-vagrant', action='store_true')
    parser.add_argument('--run-docker', action='store_true')
    parser.add_argument('arg', nargs=argparse.REMAINDER)
    parser.add_argument('--no-raise-warnings', action='store_false',
                        dest='raise_warnings', default=True)
    args = parser.parse_args()

    if args.raise_warnings:
        warnings.simplefilter('error', SignalWarning)

    default_map = {
        (None, None): (True, True),
        (None, True): (False, True),
        (True, None): (True, False)}
    unittests, functests = default_map.get((args.unittests, args.functests),
                                           (args.unittests, args.functests))

    successful = True
    if unittests:
        logging.info("Running unit tests")
        prog = Program(argv=['tests'] + args.arg, exit=False)
        successful = prog.result.wasSuccessful()
    if functests:
        logging.info("Running functional tests")
        functional_tests(args.raise_warnings,
                         args.interactive, args.run_vagrant, args.run_docker)

    if not successful:
        sys.exit(1)
