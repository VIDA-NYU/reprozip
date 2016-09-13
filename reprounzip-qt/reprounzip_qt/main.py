# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import argparse
import locale
import sys

from reprounzip_qt import __version__


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
    parser.add_argument('--unpacked', action='append')

    args = parser.parse_args()

    if args.package and args.unpacked:
        sys.stderr.write("You can't pass both a package and a unpacked "
                         "directory\n")
        sys.exit(2)
    elif args.package:
        unpack_then_run(args.package)
    elif len(args.unpacked) == 1:
        unpack(args.unpacked[0])
    elif args.unpacked:
        sys.stderr.write("You may only use --unpacked once\n")
        sys.exit(2)
    else:
        empty_gui()
    sys.exit(0)


if __name__ == '__main__':
    main()
