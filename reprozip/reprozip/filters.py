# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import logging
import re

from reprozip.tracer.trace import TracedFile


logger = logging.getLogger('reprozip')


_so_file = re.compile(r'\.so(\.[0-9]+)*$')


def builtin(input_files, **kwargs):
    """Default heuristics for input files.
    """
    for i in range(len(input_files)):
        lst = []
        for path in input_files[i]:
            if (
                # Hidden files
                path.unicodename[0] == '.' or
                # Shared libraries
                _so_file.search(path.name)
            ):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst


def python(files, input_files, **kwargs):
    add = []
    for path, fi in files.items():
        # Include .py files instead of .pyc
        if path.ext == '.pyc':
            if path.parent.name == b'__pycache__':
                # Python 3: /dir/__pycache__/mod.cpython-38.pyc -> /dir/mod.py
                basename = path.unicodename.split('.', 1)[0]
                pyfile = path.parent.parent / basename + '.py'
            else:
                # Python2: /dir/mod.pyc -> /dir/moc.py
                pyfile = path.parent / path.stem + '.py'
            if pyfile.is_file():
                if pyfile not in files:
                    logger.info("Adding %s", pyfile)
                    add.append(TracedFile(pyfile))

    for fi in add:
        files[fi.path] = fi

    for i in range(len(input_files)):
        lst = []
        for path in input_files[i]:
            if path.ext in ('.py', '.pyc'):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst
