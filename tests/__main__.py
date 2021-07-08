# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

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


from reprozip_core.common import setup_logging  # noqa
from reprounzip.signals import SignalWarning  # noqa

from tests.functional import functional_tests  # noqa

from tests.check_images import check_vagrant, check_docker  # noqa


logger = logging.getLogger('reprozip-tests')


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

    # Disable log file
    os.environ['REPROZIP_NO_LOGFILE'] = 'on'

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
    parser.add_argument('--check-vagrant-images', action='store_true',
                        default=False)
    parser.add_argument('--check-docker-images', action='store_true',
                        default=False)
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--run-vagrant', action='store_true')
    parser.add_argument('--run-docker', action='store_true')
    parser.add_argument('arg', nargs=argparse.REMAINDER)
    parser.add_argument('--no-raise-warnings', action='store_false',
                        dest='raise_warnings', default=True)
    args = parser.parse_args()

    if args.raise_warnings:
        warnings.simplefilter('error', SignalWarning)

    if not any((
        args.unittests, args.functests,
        args.check_vagrant_images, args.check_docker_images,
    )):
        unittests = functests = True
    else:
        unittests = args.unittests
        functests = args.functests

    successful = True
    if unittests:
        logger.info("Running unit tests")
        prog = Program(argv=['tests'] + args.arg, exit=False)
        successful = prog.result.wasSuccessful()
    if functests:
        logger.info("Running functional tests")
        functional_tests(args.raise_warnings,
                         args.interactive, args.run_vagrant, args.run_docker)
    if args.check_vagrant_images:
        check_vagrant()
    if args.check_docker_images:
        check_docker()

    if not successful:
        sys.exit(1)
