# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

# This file is shared:
#   reprozip/reprozip/utils.py
#   reprounzip/reprounzip/utils.py

from __future__ import unicode_literals

import email.utils
import logging
from rpaths import Path
import sys


PY3 = sys.version_info[0] == 3


if PY3:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
else:
    from urllib2 import Request, HTTPError, URLError, urlopen


if PY3:
    unicode_ = str
else:
    unicode_ = unicode


def escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


class CommonEqualityMixin(object):
    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)


def hsize(nbytes):
    """Readable size.
    """
    if nbytes is None:
        return "unknown"

    KB = 1 << 10
    MB = 1 << 20
    GB = 1 << 30
    TB = 1 << 40
    PB = 1 << 50

    nbytes = float(nbytes)

    if nbytes < KB:
        return "{0} bytes".format(nbytes)
    elif nbytes < MB:
        return "{0:.2f} KB".format(nbytes / KB)
    elif nbytes < GB:
        return "{0:.2f} MB".format(nbytes / MB)
    elif nbytes < TB:
        return "{0:.2f} GB".format(nbytes / GB)
    elif nbytes < PB:
        return "{0:.2f} TB".format(nbytes / TB)
    else:
        return "{0:.2f} PB".format(nbytes / PB)


def find_all_links_recursive(filename, files):
    path = Path('/')
    for c in filename.components[1:]:
        # At this point, path is a canonical path, and all links in it have
        # been resolved

        # We add the next path component
        path = path / c

        # That component is possibly a link
        if path.is_link():
            # Adds the link itself
            files.add(path)

            target = path.read_link(absolute=True)
            # Here, target might contain a number of symlinks
            if target not in files:
                # Recurse on this new path
                find_all_links_recursive(target, files)
            # Restores the invariant; realpath might resolve several links here
            path = path.resolve()
    return path


def find_all_links(filename, include_target=False):
    """Dereferences symlinks from a path.

    If include_target is True, this also returns the real path of the final
    target.

    Example:
        /
            a -> b
            b
                g -> c
                c -> ../a/d
                d
                    e -> /f
            f
    >>> find_all_links('/a/g/e', True)
    ['/a', '/b/c', '/b/g', '/b/d/e', '/f']
    """
    files = set()
    filename = Path(filename)
    assert filename.absolute()
    path = find_all_links_recursive(filename, files)
    files = list(files)
    if include_target:
        files.append(path)
    return files


def download_file(url, dest, cachename=None):
    if cachename is None:
        cachename = dest.name

    request = Request(url)

    cache = Path('~/.cache/reprozip').expand_user() / cachename
    if cache.exists():
        mtime = email.utils.formatdate(cache.mtime(), usegmt=True)
        request.add_header('If-Modified-Since', mtime)

    try:
        response = urlopen(request)
    except URLError as e:
        if cache.exists():
            if isinstance(e, HTTPError) and e.code == 304:
                logging.info("Cached file %s is up to date" % cachename)
            else:
                logging.warning("Couldn't download %s: %s" % (url, e))
            cache.copy(dest)
            return
        else:
            raise

    if response is None:
        logging.info("Cached file %s is up to date" % cachename)
        cache.copy(dest)
        return

    logging.info("Downloading %s" % url)
    try:
        CHUNK_SIZE = 4096
        cache.parent.mkdir(parents=True)
        with cache.open('wb') as f:
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
        response.close()
    except Exception as e:
        try:
            cache.remove()
        except OSError:
            pass
        raise e

    cache.copy(dest)
