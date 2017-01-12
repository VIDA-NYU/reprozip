# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import argparse
import locale
import sys

from reprounzip_qt import __version__


def qt_init():
    import sip

    sip.setapi('QString', 2)
    sip.setapi('QVariant', 2)

    from PyQt4 import QtGui

    return QtGui.QApplication(sys.argv)


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
    parser.add_argument('package', nargs=argparse.OPTIONAL)
    parser.add_argument('--unpacked', action='append', default=[])

    args = parser.parse_args()

    app = qt_init()

    from reprounzip_qt.gui import ReprounzipUi

    window_args = {}
    if args.package and args.unpacked:
        sys.stderr.write("You can't pass both a package and a unpacked "
                         "directory\n")
        sys.exit(2)
    elif args.package:
        window_args = dict(unpack=dict(package=args.package))
    elif len(args.unpacked) == 1:
        window_args = dict(run=dict(unpacked_directory=args.unpacked[0]),
                           tab=1)
    elif args.unpacked:
        sys.stderr.write("You may only use --unpacked once\n")
        sys.exit(2)

    window = ReprounzipUi(**window_args)
    window.setVisible(True)

    app.exec_()
    sys.exit(0)


if __name__ == '__main__':
    main()
