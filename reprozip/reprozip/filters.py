# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import logging
import re
from rpaths import Path

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


def ruby_gems_and_apps(files, input_files, **kwargs):
    extensions = list(map(lambda ext: ext.encode('utf-8'),
                          ['.rb',
                           '.haml',
                           '.slim',
                           '.erb',
                           '.js',
                           '.html']))
    ignored_dirs = list(map(lambda ext: ext.encode('utf-8'),
                            ['spec',
                             'test',
                             'tests',
                             'guides',
                             'doc-api',
                             'rdoc',
                             'doc']))

    gemy_path = re.compile(r'.*\/ruby-[^/]*\/gems')
    appdir_paths = re.compile(r'.*\/app\/(views|'
                              'controllers|models|'
                              'helpers)$')

    seen_paths = []
    add = []

    def consume(dir_or_file):
        dir_or_file = Path(dir_or_file)
        if (dir_or_file.is_file()
            and dir_or_file.ext in extensions
                and dir_or_file not in files):
            logger.info("Adding %s", dir_or_file)
            add.append(TracedFile(dir_or_file))
        elif (dir_or_file.is_dir()
              and dir_or_file.name not in ignored_dirs):
            for child in dir_or_file.listdir():
                consume(child)

    for path, fi in iteritems(files):
        m1 = gemy_path.match(str(path))
        if m1 and m1.group(0) not in seen_paths:
            consume(m1.group(0))
            seen_paths.append(m1.group(0))
        elif m1:
            continue

        m2 = appdir_paths.match(str(path))
        if (m2 and m2.group(0) not in seen_paths
            and (path.parent.parent /
                 'config/application.rb').is_file()):
            consume(m2.group(0))
            seen_paths.append(m2.group(0))

    for fi in add:
        files[fi.path] = fi
