# This file is shared:
#   reprozip/reprozip/utils.py
#   reprounzip/reprounzip/utils.py

from __future__ import unicode_literals

import os


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
        return "{} bytes".format(nbytes)
    elif nbytes < MB:
        return "{:.2f} KB".format(nbytes / KB)
    elif nbytes < GB:
        return "{:.2f} MB".format(nbytes / MB)
    elif nbytes < TB:
        return "{:.2f} GB".format(nbytes / GB)
    elif nbytes < PB:
        return "{:.2f} TB".format(nbytes / TB)
    else:
        return "{:.2f} PB".format(nbytes / PB)


def find_all_links_recursive(filename, files):
    # We assume that filename is an abspath, so we can just split on os.sep
    path = '/'
    for c in filename.split(os.sep)[1:]:
        # At this point, path is a canonical path, and all links in it have
        # been resolved

        # We add the next path component
        path = os.path.join(path, c)

        # That component is possibly a link
        if os.path.islink(path):
            target = os.path.abspath(os.path.join(os.path.dirname(path),
                                                  os.readlink(path)))
            # Here, target might contain a number of symlinks
            if target not in files:
                # Adds the link itself
                files.add(path)

                # Recurse on this new path
                find_all_links_recursive(target, files)
            # Restores the invariant; realpath might resolve several links here
            path = os.path.realpath(path)
    return path


def find_all_links(filename):
    """Dereferences symlinks from a path, returning them plus the final target.

    Example:
        /
            a -> b
            b
                g -> c
                c -> ../a/d
                d
                    e -> /f
            f
    >>> find_all_links('/a/g/e')
    ['/a', '/b/c', '/b/g', '/b/d/e', '/f']
    """
    files = set()
    path = find_all_links_recursive(filename, files)
    return list(files) + [path]


def makedir(path):
    if not os.path.exists(path):
        makedir(os.path.dirname(path))
        try:
            os.mkdir(path)
        except OSError:
            pass
