# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import logging
import re

from reprozip.tracer.trace import TracedFile
from reprozip.utils import irange, iteritems


logger = logging.getLogger('reprozip')


_so_file = re.compile(br'\.so(\.[0-9]+)*$')


def builtin(input_files, **kwargs):
    """Default heuristics for input files.
    """
    for i in irange(len(input_files)):
        lst = []
        for path in input_files[i]:
            if (
                    # Hidden files
                    path.unicodename[0] == '.' or
                    # Shared libraries
                    _so_file.search(path.name)):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst


def python(files, input_files, **kwargs):
    add = []
    for path, fi in iteritems(files):
        if path.ext == b'.pyc':
            pyfile = path.parent / path.stem + '.py'
            if pyfile.is_file():
                if pyfile not in files:
                    logger.info("Adding %s", pyfile)
                    add.append(TracedFile(pyfile))

    for fi in add:
        files[fi.path] = fi

    for i in irange(len(input_files)):
        lst = []
        for path in input_files[i]:
            if path.ext in (b'.py', b'.pyc'):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst
