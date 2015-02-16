# Copyright (C) 2014-2015 New York University
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

import atexit
from datetime import datetime
from distutils.version import LooseVersion
import logging
import logging.handlers
import os
from rpaths import PosixPath, Path
import sys
import usagestats
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


# Pack format history:
# 0.2: used by reprozip 0.2
# 0.2.1:
#     config: comments directories as such in config
#     trace database: adds executed_files.workingdir, adds processes.exitcode
#     data: packs dynamic linkers
# 0.3:
#     config: don't list missing (unpacked) files in config
#     trace database: adds opened_files.is_directory
# 0.3.1: no change
# 0.3.2: no change
# 0.4:
#     config: adds input_files, output_files, lists parent directories
# 0.4.1: no change
# 0.5: no change


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
    # Accepts versions from 0.2 to 0.6 inclusive
    elif not LooseVersion('0.2') <= ver < LooseVersion('0.7'):
        pkgname = (__package__ or __name__).split('.', 1)[0]
        raise InvalidConfig("Loading configuration file in unknown format %s; "
                            "this probably means that you should upgrade "
                            "%s" % (ver, pkgname))
    unknown_keys = keys_ - set(['pack_id', 'version', 'runs',
                                'packages', 'other_files',
                                'additional_patterns'])
    if unknown_keys:
        logging.warning("Unrecognized sections in configuration: %s",
                        ', '.join(unknown_keys))

    runs = config.get('runs', [])
    packages = read_packages(config.get('packages', []), File, Package)
    other_files = read_files(config.get('other_files', []), File)

    # Adds 'input_files' and 'output_files' keys to runs
    for run in runs:
        if 'input_files' not in run:
            run['input_files'] = {}
        if 'output_files' not in run:
            run['output_files'] = {}

    record_usage_package(runs, packages, other_files,
                         pack_id=config.get('pack_id'))

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
                canonical=False, pack_id=None):
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

# Run info{pack_id}
version: "{format!s}"
""".format(pack_id=(('\npack_id: "%s"' % pack_id) if pack_id is not None
                    else ''),
           version=escape(reprozip_version),
           format='0.4',
           date=datetime.now().isoformat(),
           what=("# It was generated by the packer and you shouldn't need to "
                 "edit it" if canonical
                 else "# You might want to edit this file before running the "
                 "packer\n# See 'reprozip pack -h' for help")))
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
    console_level = levels[min(verbosity, 3)]
    file_level = logging.INFO
    min_level = min(console_level, file_level)

    # Create formatter, with same format as C extension
    fmt = "[%s] %%(asctime)s %%(levelname)s: %%(message)s" % tag
    formatter = LoggingDateFormatter(fmt)

    # Console logger
    handler = logging.StreamHandler()
    handler.setLevel(console_level)
    handler.setFormatter(formatter)

    # Set up logger
    logger = logging.root
    logger.setLevel(min_level)
    logger.addHandler(handler)

    # File logger
    dotrpz = Path('~/.reprozip').expand_user()
    try:
        if not dotrpz.is_dir():
            dotrpz.mkdir()
        filehandler = logging.handlers.RotatingFileHandler(str(dotrpz / 'log'),
                                                           mode='a',
                                                           delay=False,
                                                           maxBytes=400000,
                                                           backupCount=5)
    except (IOError, OSError):
        logging.warning("Couldn't create log file %s", dotrpz / 'log')
    else:
        filehandler.setFormatter(formatter)
        filehandler.setLevel(file_level)
        logger.addHandler(filehandler)


_usage_report = None


def setup_usage_report(name, version):
    """Sets up the usagestats module.
    """
    global _usage_report

    # Unpack CA certificate
    fd, certificate_file = Path.tempfile(prefix='rpz_stats_ca_', suffix='.pem')
    with certificate_file.open('wb') as fp:
        fp.write(usage_report_ca)
    os.close(fd)
    atexit.register(os.remove, certificate_file.path)

    _usage_report = usagestats.Stats(
            '~/.reprozip/usage_stats',
            usagestats.Prompt(enable='%s usage_report --enable' % name,
                              disable='%s usage_report --disable' % name),
            os.environ.get('REPROZIP_USAGE_URL',
                           'https://reprozip-stats.poly.edu/'),
            version='%s %s' % (name, version),
            unique_user_id=True,
            env_var='REPROZIP_USAGE_STATS',
            ssl_verify=certificate_file.path)
    try:
        os.getcwd().encode('ascii')
    except (UnicodeEncodeError, UnicodeDecodeError):
        record_usage(cwd_ascii=False)
    else:
        record_usage(cwd_ascii=True)


def enable_usage_report(enable):
    """Enables or disables usage reporting.
    """
    if enable:
        _usage_report.enable_reporting()
        sys.stderr.write("Thank you, usage reports will be sent automatically "
                         "from now on.\n")
    else:
        _usage_report.disable_reporting()
        sys.stderr.write("Usage reports will not be collected nor sent.\n")


def record_usage(**kwargs):
    """Records some info in the current usage report.
    """
    _usage_report.note(kwargs)


def record_usage_package(runs, packages, other_files, pack_id=None):
    """Records the info on some pack file into the current usage report.
    """
    for run in runs:
        record_usage(argv0=run['argv'][0])
    record_usage(pack_id=pack_id or '',
                 nb_packages=len(packages),
                 nb_package_files=sum(len(pkg.files)
                                      for pkg in packages),
                 packed_packages=sum(1 for pkg in packages
                                     if pkg.packfiles),
                 nb_other_files=len(other_files))


def submit_usage_report(**kwargs):
    """Submits the current usage report to the usagestats server.
    """
    _usage_report.submit(kwargs,
                         usagestats.OPERATING_SYSTEM,
                         usagestats.SESSION_TIME,
                         usagestats.PYTHON_VERSION)


usage_report_ca = b'''\
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIJAMmlcDnTidBEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3IFlvcmsxDDAK
BgNVBAoMA05ZVTERMA8GA1UEAwwIUmVwcm9aaXAxKDAmBgkqhkiG9w0BCQEWGXJl
cHJvemlwLWRldkB2Z2MucG9seS5lZHUwHhcNMTQxMTA3MDUxOTA5WhcNMjQxMTA0
MDUxOTA5WjB+MQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxETAPBgNV
BAcMCE5ldyBZb3JrMQwwCgYDVQQKDANOWVUxETAPBgNVBAMMCFJlcHJvWmlwMSgw
JgYJKoZIhvcNAQkBFhlyZXByb3ppcC1kZXZAdmdjLnBvbHkuZWR1MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1fuTW2snrVji51vGVl9hXAAZbNJ+dxG+
/LOOxZrF2f1RRNy8YWpeCfGbsZqiIEjorBv8lvdd9P+tD3M5sh9L0zQPU9dFvDb+
OOrV0jx59hbK3QcCQju3YFuAtD1lu8TBIPgGEab0eJhLVIX+XU5cYXrfoBmwCpN/
1wXWkUhN91ZVMA0ylATAxTpnoNuMKzfTxT8pyOWajiTskYkKmVBAxgYJQe1YDFA8
fglBNkQuHqP8jgYAniEBCAPZRMMq8WpOtyFx+L9LX9/WcHtAQyDPPb9M81KKgPQq
urtCqtuDKxuqcX9zg4/O8l4nZ50pwaJjbH4kMW/wnLzTPvzZCPtJYQIDAQABo1Aw
TjAdBgNVHQ4EFgQUJjhDDOup4P0cdrAVq1F9ap3yTj8wHwYDVR0jBBgwFoAUJjhD
DOup4P0cdrAVq1F9ap3yTj8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAeKpTiy2WYPqevHseTCJDIL44zghDJ9w5JmECOhFgPXR9Hl5Nh9S1j4qHBs4G
cn8d1p2+8tgcJpNAysjuSl4/MM6hQNecW0QVqvJDQGPn33bruMB4DYRT5du1Zpz1
YIKRjGU7Of3CycOCbaT50VZHhEd5GS2Lvg41ngxtsE8JKnvPuim92dnCutD0beV+
4TEvoleIi/K4AZWIaekIyqazd0c7eQjgSclNGgePcdbaxIo0u6tmdTYk3RNzo99t
DCfXxuMMg3wo5pbqG+MvTdECaLwt14zWU259z8JX0BoeVG32kHlt2eUpm5PCfxqc
dYuwZmAXksp0T0cWo0DnjJKRGQ==
-----END CERTIFICATE-----
'''
