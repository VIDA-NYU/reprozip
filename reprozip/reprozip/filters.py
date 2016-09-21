# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from reprozip.tracer.trace import TracedFile
from reprozip.utils import iteritems


def python(files):
    remove = []
    add = []
    for path, fi in iteritems(files):
        if path.ext == '.pyc':
            pyfile = path.parent / path.stem + '.py'
            if pyfile.is_file():
                remove.append(path)
                pyfile = path.parent / path.stem + '.py'
                if pyfile not in files:
                    add.append(TracedFile(pyfile))

    for path in remove:
        files.pop(path, None)

    for fi in add:
        files[fi.path] = fi
