# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

# This file is shared:
#   reprozip/reprozip/common.py
#   reprounzip/reprounzip/common.py

"""Common functions between reprozip and reprounzip.

This module contains functions that are specific to the reprozip software and
its data formats, but that are shared between the reprozip and reprounzip
packages. Because the packages can be installed separately, these functions are
in a separate module which is duplicated between the packages.

As long as these are small in number, they are not worth putting in a separate
package that reprozip and reprounzip would both depend on.

"""

from __future__ import unicode_literals

from datetime import datetime
from distutils.version import LooseVersion
import logging
from rpaths import PosixPath
import yaml

from .utils import CommonEqualityMixin, escape, hsize, unicode_


FILE_READ = 0x01
FILE_WRITE = 0x02
FILE_WDIR = 0x04
FILE_STAT = 0x08


class File(CommonEqualityMixin):
    """A file, used at some point during the experiment.
    """
    comment = None

    def __init__(self, path, size=None):
        self.path = path
        self.size = size

    def __eq__(self, other):
        return (isinstance(other, File) and
                self.path == other.path)

    def __hash__(self):
        return hash(self.path)


class Package(CommonEqualityMixin):
    """A distribution package, containing a set of files.
    """
    def __init__(self, name, version, files=None, packfiles=True, size=None):
        self.name = name
        self.version = version
        self.files = list(files) if files is not None else []
        self.packfiles = packfiles
        self.size = size

    def add_file(self, filename):
        self.files.append(filename)

    def __unicode__(self):
        return '%s (%s)' % (self.name, self.version)
    __str__ = __unicode__


class InvalidConfig(ValueError):
    """Configuration file is invalid.
    """


def read_files(files, File=File):
    if files is None:
        return []
    return [File(PosixPath(f)) for f in files]


def read_packages(packages, File=File, Package=Package):
    if packages is None:
        return []
    new_pkgs = []
    for pkg in packages:
        pkg['files'] = read_files(pkg['files'], File)
        new_pkgs.append(Package(**pkg))
    return new_pkgs


def load_config(filename, canonical, File=File, Package=Package):
    """Loads a YAML configuration file.

    `File` and `Package` parameters can be used to override the classes that
    will be used to hold files and distribution packages; useful during the
    packing step.

    `canonical` indicates whether a canonical configuration file is expected
    (in which case the ``additional_patterns`` section is not accepted). Note
    that this changes the number of returned values of this function.
    """
    with filename.open(encoding='utf-8') as fp:
        config = yaml.safe_load(fp)

    ver = LooseVersion(config['version'])

    keys_ = set(config)
    if 'version' not in keys_:
        raise InvalidConfig("Missing version")
    # Accepts versions from 0.2 to 0.4 inclusive
    elif not LooseVersion('0.2') <= ver < LooseVersion('0.5'):
        raise InvalidConfig("Unknown version")
    elif not keys_.issubset(set(['version', 'runs',
                                 'packages', 'other_files',
                                 'additional_patterns'])):
        raise InvalidConfig("Unrecognized sections")

    runs = config.get('runs', [])
    packages = read_packages(config.get('packages', []), File, Package)
    other_files = read_files(config.get('other_files', []), File)

    # Adds 'input_files' and 'output_files' keys to runs
    for run in runs:
        if 'input_files' not in run:
            run['input_files'] = {}
        if 'output_files' not in run:
            run['output_files'] = {}

    if canonical:
        if 'additional_patterns' in config:
            raise InvalidConfig("Canonical configuration file shouldn't have "
                                "additional_patterns key anymore")
        return runs, packages, other_files
    else:
        additional_patterns = config.get('additional_patterns') or []
        return runs, packages, other_files, additional_patterns


def write_file(fp, fi, indent=0):
    fp.write("%s  - \"%s\"%s\n" % (
             "    " * indent,
             escape(unicode_(fi.path)),
             ' # %s' % fi.comment if fi.comment is not None else ''))


def write_package(fp, pkg, indent=0):
    indent_str = "    " * indent
    fp.write("%s  - name: \"%s\"\n" % (indent_str, escape(pkg.name)))
    fp.write("%s    version: \"%s\"\n" % (indent_str, escape(pkg.version)))
    if pkg.size is not None:
        fp.write("%s    size: %d\n" % (indent_str, pkg.size))
    fp.write("%s    packfiles: %s\n" % (indent_str, 'true' if pkg.packfiles
                                                    else 'false'))
    fp.write("%s    files:\n"
             "%s      # Total files used: %s\n" % (
                 indent_str, indent_str,
                 hsize(sum(fi.size
                           for fi in pkg.files
                           if fi.size is not None))))
    if pkg.size is not None:
        fp.write("%s      # Installed package size: %s\n" % (
                 indent_str, hsize(pkg.size)))
    for fi in sorted(pkg.files, key=lambda fi_: fi_.path):
        write_file(fp, fi, indent + 1)


def save_config(filename, runs, packages, other_files, reprozip_version,
                canonical=False):
    """Saves the configuration to a YAML file.

    `canonical` indicates whether this is a canonical configuration file
    (no ``additional_patterns`` section).
    """
    dump = lambda x: yaml.safe_dump(x, encoding='utf-8', allow_unicode=True)
    with filename.open('w', encoding='utf-8', newline='\n') as fp:
        # Writes preamble
        fp.write("""\
# ReproZip configuration file
# This file was generated by reprozip {version} at {date}

{what}

# Run info
version: "{version!s}"
""".format(version=escape(reprozip_version),
           date=datetime.now().isoformat(),
           what="# It was generated by the packer and you shouldn't need to "
           "edit it" if canonical
           else "# You might want to edit this file before running the "
           "packer\n# See 'reprozip pack -h' for help"))
        fp.write(dump({'runs': runs}).decode('utf-8'))
        fp.write("""\

# Files to pack
# All the files below were used by the program; they will be included in the
# generated package

# These files come from packages; we can thus choose not to include them, as it
# will simply be possible to install that package on the destination system
# They are included anyway by default
packages:
""")

        # Writes files
        for pkg in sorted(packages, key=lambda p: p.name):
            write_package(fp, pkg)

        fp.write("""\

# These files do not appear to come with an installed package -- you probably
# want them packed
other_files:
""")
        for f in sorted(other_files, key=lambda fi: fi.path):
            write_file(fp, f)

        if not canonical:
            fp.write("""\

# If you want to include additional files in the pack, you can list additional
# patterns of files that will be included
# Example:
#additional_patterns:
#  - /etc/apache2/**  # Everything under apache2/
#  - /var/log/apache2/*.log  # Log files directly under apache2/
#  - /var/lib/lxc/*/rootfs/home/**/*.py  # All Python files of all users in
#    # that container
""")


class LoggingDateFormatter(logging.Formatter):
    """Formatter that puts milliseconds in the timestamp.
    """
    converter = datetime.fromtimestamp

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        t = ct.strftime("%H:%M:%S")
        s = "%s.%03d" % (t, record.msecs)
        return s


def setup_logging(tag, verbosity):
    """Sets up the logging module.
    """
    levels = [logging.CRITICAL, logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, 3)]

    fmt = "[%s] %%(asctime)s %%(levelname)s: %%(message)s" % tag

    formatter = LoggingDateFormatter(fmt)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.root
    logger.setLevel(level)
    logger.addHandler(handler)
