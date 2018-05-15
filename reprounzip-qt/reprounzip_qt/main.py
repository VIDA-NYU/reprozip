# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import argparse
import locale
import logging
import sys

from reprounzip.common import setup_logging
from reprounzip_qt import __version__
from reprounzip_qt.usage import record_usage, submit_usage_report


logger = logging.getLogger('reprounzip_qt')


def qt_init():
    import sip

    sip.setapi('QString', 2)
    sip.setapi('QVariant', 2)

    from PyQt4 import QtGui  # noqa


def main():
    """Entry point when called on the command-line.
    """
    # Locale
    locale.setlocale(locale.LC_ALL, '')

    parser = argparse.ArgumentParser(
        description="Graphical user interface for reprounzip",
        epilog="Please report issues to reprozip-users@vgc.poly.edu")
    parser.add_argument('--version', action='version',
                        version="reprounzip-qt version %s" % __version__)
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        dest='verbosity', help="augments verbosity level")
    parser.add_argument('package', nargs=argparse.OPTIONAL)
    parser.add_argument('--unpacked', action='append', default=[])

    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i].startswith('-psn'):
            del argv[i]
        else:
            i += 1
    args = parser.parse_args(argv)

    setup_logging('REPROUNZIP-QT', args.verbosity)

    qt_init()

    from reprounzip_qt.gui import Application, ReprounzipUi

    app = Application(sys.argv)

    window_args = {}
    if args.package and args.unpacked:
        sys.stderr.write("You can't pass both a package and a unpacked "
                         "directory\n")
        sys.exit(2)
    elif args.package:
        logger.info("Got package on the command-line: %s", args.package)
        record_usage(cmdline='package')
        window_args = dict(unpack=dict(package=args.package))
    elif len(args.unpacked) == 1:
        logger.info("Got unpacked directory on the command-line: %s",
                    args.unpacked)
        record_usage(cmdline='directory')
        window_args = dict(run=dict(unpacked_directory=args.unpacked[0]),
                           tab=1)
    elif args.unpacked:
        sys.stderr.write("You may only use --unpacked once\n")
        sys.exit(2)
    else:
        record_usage(cmdline='empty')

    window = ReprounzipUi(**window_args)
    app.set_first_window(window)
    window.setVisible(True)

    app.exec_()
    submit_usage_report()
    sys.exit(0)


if __name__ == '__main__':
    main()
