# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import logging
import re
from pathlib import Path

from reprozip_core.common import File


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
                path.name[0] == '.' or
                # Shared libraries
                _so_file.search(path.name)
            ):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst


def python(files, input_files, **kwargs):
    add = []
    remove = set()
    for path, fi in files.items():
        # Include .py files instead of .pyc
        if path.suffix == '.pyc':
            if path.parent.name == '__pycache__':
                # Python 3: /dir/__pycache__/mod.cpython-38.pyc -> /dir/mod.py
                basename = path.name.split('.', 1)[0]
                pyfile = path.parent.parent / (basename + '.py')
            else:
                # Python2: /dir/mod.pyc -> /dir/moc.py
                pyfile = path.parent / (path.stem + '.py')
            if pyfile.is_file():
                if pyfile not in files:
                    logger.info("Adding %s", pyfile)
                    add.append(File(pyfile))
                logger.info("Removing %s", path)
                remove.add(path)

    for fi in add:
        files[fi.path] = fi
    for path in remove:
        files.pop(path, None)

    for i in range(len(input_files)):
        lst = []
        for path in input_files[i]:
            if (
                path.suffix in ('.py', '.pyc')
                or (
                    'site-packages' in path.parts
                    and path.suffix == '.pth'
                )
                or any(part.endswith('.dist-info') for part in path.parts)
            ):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst


def ruby(files, input_files, **kwargs):
    extensions = {'.rb', '.haml', '.slim', '.erb', '.js', '.html'}
    ignored_dirs = {
        'spec', 'test', 'tests', 'guides', 'doc-api', 'rdoc', 'doc',
    }

    gemy_path = re.compile(r'^.*/ruby[-/]\d+\.\d+\.\d+/gems')
    appdir_paths = re.compile(r'^.*/app/(views|controllers|models|helpers)')

    directories = set()

    for path, fi in files.items():
        m1 = gemy_path.match(str(path))
        if m1:
            directories.add(Path(m1.group(0)))

        m2 = appdir_paths.match(str(path))
        if m2:
            app_root = Path(m2.group(0)).parent.parent
            if (app_root / 'config/application.rb').is_file():
                directories.add(app_root)

    def add_recursive(dir_or_file):
        if (
            dir_or_file.is_file()
            and dir_or_file.suffix in extensions
        ):
            logger.info("Adding %s", dir_or_file)
            files[dir_or_file] = File(dir_or_file)
        elif (
            dir_or_file.is_dir()
            and dir_or_file.name not in ignored_dirs
        ):
            for child in dir_or_file.iterdir():
                add_recursive(child)

    for directory in directories:
        add_recursive(directory)

    for i in range(len(input_files)):
        lst = []
        for path in input_files[i]:
            if gemy_path.match(str(path)) or appdir_paths.match(str(path)):
                logger.info("Removing input %s", path)
            else:
                lst.append(path)

        input_files[i] = lst
