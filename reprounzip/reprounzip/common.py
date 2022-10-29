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

from __future__ import division, print_function, unicode_literals

import atexit
import contextlib
import copy
from datetime import datetime
from distutils.version import LooseVersion
import functools
import gzip
import logging
import logging.handlers
import os
from rpaths import PosixPath, Path
import sys
import tarfile
import usagestats
import yaml
import zipfile

from .utils import iteritems, itervalues, unicode_, stderr, UniqueNames, \
    escape, optional_return_type, isodatetime, hsize, join_root, copyfile


logger = logging.getLogger(__name__.split('.', 1)[0])


FILE_READ = 0x01
FILE_WRITE = 0x02
FILE_WDIR = 0x04
FILE_STAT = 0x08
FILE_LINK = 0x10


class File(object):
    """A file, used at some point during the experiment.
    """
    comment = None

    def __init__(self, path, size=None):
        self.path = path
        self.size = size

    def __eq__(self, other):
        return (isinstance(other, File) and
                self.path == other.path)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.path)


class Package(object):
    """A distribution package, containing a set of files.
    """
    def __init__(self, name, version, files=None, packfiles=True, size=None):
        self.name = name
        self.version = version
        self.files = list(files) if files is not None else []
        self.packfiles = packfiles
        self.size = size

    def __eq__(self, other):
        return (isinstance(other, Package) and
                self.name == other.name and
                self.version == other.version)

    def __ne__(self, other):
        return not self.__eq__(other)

    def add_file(self, file_):
        self.files.append(file_)

    def __unicode__(self):
        return '%s (%s)' % (self.name, self.version)
    __str__ = __unicode__


# Pack format history:
# 1: used by reprozip 0.2 through 0.7. Single tar.gz file, metadata under
#   METADATA/, data under DATA/
# 2: pack is usually not compressed, metadata under METADATA/, data in another
#   DATA.tar.gz (files inside it still have the DATA/ prefix for ease-of-use
#   in unpackers)
#
# Pack metadata history:
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
# 0.6: no change
# 0.7:
#     moves input_files and output_files from run to global scope
#     adds processes.is_thread column to trace database
# 0.8: adds 'id' field to run


class RPZPack(object):
    """Encapsulates operations on the RPZ pack format.
    """
    data = zip = tar = None

    def __init__(self, pack):
        self.pack = Path(pack)

        if self._open_tar():
            pass
        elif self._open_zip():
            pass
        else:
            raise ValueError("File doesn't appear to be an RPZ pack")

    def _open_tar(self):
        try:
            self.tar = tarfile.open(str(self.pack), 'r:*')
        except tarfile.TarError:
            return False
        try:
            f = self.tar.extractfile('METADATA/version')
        except KeyError:
            raise ValueError("Invalid ReproZip file")
        version = f.read()
        f.close()
        if version.startswith(b'REPROZIP VERSION '):
            try:
                version = int(version[17:].rstrip())
            except ValueError:
                version = None
            if version in (1, 2):
                self.version = version
                self.data_prefix = PosixPath(b'DATA')
            else:
                raise ValueError(
                    "Unknown format version %r (maybe you should upgrade "
                    "reprounzip? I only know versions 1 and 2" % version)
        else:
            raise ValueError("File doesn't appear to be an RPZ pack")

        if self.version == 1:
            self.data = self.tar
        elif version == 2:
            self.data = tarfile.open(
                fileobj=self.tar.extractfile('DATA.tar.gz'),
                mode='r:*')
        else:
            assert False
        return True

    def _open_zip(self):
        try:
            self.zip = zipfile.ZipFile(str(self.pack))
        except zipfile.BadZipfile:
            return False
        try:
            f = self.zip.open('METADATA/version')
        except KeyError:
            raise ValueError("Invalid ReproZip file")
        version = f.read()
        f.close()
        if version.startswith(b'REPROZIP VERSION '):
            try:
                version = int(version[17:].rstrip())
            except ValueError:
                version = None
            if version == 1:
                raise ValueError("Format version 1 is not accepted for ZIP")
            elif version == 2:
                self.version = 2
                self.data_prefix = PosixPath(b'DATA')
            else:
                raise ValueError(
                    "Unknown format version %r (maybe you should upgrade "
                    "reprounzip? I only know versions 1 and 2" % version)
        else:
            raise ValueError("File doesn't appear to be an RPZ pack")

        if sys.version_info < (3, 7):
            # zip.open() doesn't return a seekable file object before 3.6
            # Extract to a temporary file instead
            fd, temporary_data = Path.tempfile(
                prefix='reprounzip_data_',
                suffix='.zip',
            )
            os.close(fd)
            self._extract_file('DATA.tar.gz', temporary_data)
            self.data = tarfile.open(str(temporary_data), mode='r:*')
            atexit.register(os.remove, temporary_data.path)
        else:
            self.data = tarfile.open(fileobj=self.zip.open('DATA.tar.gz'),
                                     mode='r:*')
        return True

    def remove_data_prefix(self, path):
        if not isinstance(path, PosixPath):
            path = PosixPath(path)
        components = path.components[1:]
        if not components:
            return path.__class__('')
        return path.__class__(*components)

    def open_config(self):
        """Gets the configuration file.
        """
        if self.tar is not None:
            return self.tar.extractfile('METADATA/config.yml')
        else:
            return self.zip.open('METADATA/config.yml')

    def extract_config(self, target):
        """Extracts the config to the specified path.

        It is up to the caller to remove that file once done.
        """
        self._extract_file('METADATA/config.yml', target)

    def _extract_file(self, name, target):
        if self.tar is not None:
            member = copy.copy(self.tar.getmember(name))
            member.name = str(target.components[-1])
            self.tar.extract(member, path=str(Path.cwd() / target.parent))
        else:
            member = copy.copy(self.zip.getinfo(name))
            member.filename = str(target.components[-1])
            self.zip.extract(member, path=str(Path.cwd() / target.parent))
        target.chmod(0o644)
        assert target.is_file()

    def _extract_file_gz(self, name, target):
        if self.tar is not None:
            f_in = self.tar.extractfile(name)
        else:
            f_in = self.zip.open(name)
        f_in_gz = gzip.open(f_in)
        f_out = target.open('wb')
        try:
            chunk = f_in_gz.read(4096)
            while len(chunk) == 4096:
                f_out.write(chunk)
                chunk = f_in_gz.read(4096)
            if chunk:
                f_out.write(chunk)
        finally:
            f_out.close()
            f_in_gz.close()
            f_in.close()
        target.chmod(0o644)

    @contextlib.contextmanager
    def with_config(self):
        """Context manager that extracts the config to  a temporary file.
        """
        fd, tmp = Path.tempfile(prefix='reprounzip_')
        os.close(fd)
        self.extract_config(tmp)
        yield tmp
        tmp.remove()

    def extract_trace(self, target):
        """Extracts the trace database to the specified path.

        It is up to the caller to remove that file once done.
        """
        target = Path(target)
        if self.version == 2:
            try:
                if self.tar is not None:
                    self.tar.getmember('METADATA/trace.sqlite3.gz')
                else:
                    self.zip.getinfo('METADATA/trace.sqlite3.gz')
            except KeyError:
                pass
            else:
                self._extract_file_gz('METADATA/trace.sqlite3.gz', target)
                return
        elif self.version != 2:
            assert False
        self._extract_file('METADATA/trace.sqlite3', target)

    @contextlib.contextmanager
    def with_trace(self):
        """Context manager extracting the trace database to a temporary file.
        """
        fd, tmp = Path.tempfile(prefix='reprounzip_')
        os.close(fd)
        self.extract_trace(tmp)
        yield tmp
        tmp.remove()

    def list_data(self):
        """Returns tarfile.TarInfo objects for all the data paths.
        """
        return [copy.copy(m)
                for m in self.data.getmembers()
                if m.name.startswith('DATA/')]

    def data_filenames(self):
        """Returns a set of filenames for all the data paths.

        Those paths begin with a slash / and the 'DATA' prefix has been
        removed.
        """
        return set(PosixPath(m.name[4:])
                   for m in self.data.getmembers()
                   if m.name.startswith('DATA/'))

    def get_data(self, path):
        """Returns a tarfile.TarInfo object for the data path.

        Raises KeyError if no such path exists.
        """
        path = PosixPath(path)
        path = join_root(PosixPath(b'DATA'), path)
        return copy.copy(self.data.getmember(path))

    def extract_data(self, root, members):
        """Extracts the given members from the data tarball.

        The members must come from get_data().
        """
        # Check for CVE-2007-4559
        abs_root = root.absolute()
        for member in members:
            member_path = (root / member.name).absolute()
            if not member_path.lies_under(abs_root):
                raise ValueError("Invalid path in data tar")

        self.data.extractall(str(root), members)

    def copy_data_tar(self, target):
        """Copies the file in which the data lies to the specified destination.
        """
        if self.tar is not None:
            if self.version == 1:
                self.pack.copyfile(target)
            elif self.version == 2:
                with target.open('wb') as fp:
                    data = self.tar.extractfile('DATA.tar.gz')
                    copyfile(data, fp)
                    data.close()
        else:
            with target.open('wb') as fp:
                data = self.zip.open('DATA.tar.gz')
                copyfile(data, fp)
                data.close()

    def extensions(self):
        """Get a list of extensions present in this pack.
        """
        extensions = set()
        if self.tar is not None:
            for m in self.tar.getmembers():
                if m.name.startswith('EXTENSIONS/'):
                    name = m.name[11:]
                    if '/' in name:
                        name = name[:name.index('/')]
                    if name:
                        extensions.add(name)
        else:
            for m in self.zip.infolist():
                if m.filename.startswith('EXTENSIONS/'):
                    name = m.filename[11:]
                    if '/' in name:
                        name = name[:name.index('/')]
                    if name:
                        extensions.add(name)
        return extensions

    def close(self):
        if self.data is not self.tar:
            self.data.close()
        if self.tar is not None:
            self.tar.close()
        elif self.zip is not None:
            self.zip.close()
        self.data = self.zip = self.tar = None


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


Config = optional_return_type(['runs', 'packages', 'other_files'],
                              ['inputs_outputs', 'additional_patterns',
                               'format_version'])


@functools.total_ordering
class InputOutputFile(object):
    def __init__(self, path, read_runs, write_runs):
        self.path = path
        self.read_runs = read_runs
        self.write_runs = write_runs

    def __eq__(self, other):
        return ((self.path, self.read_runs, self.write_runs) ==
                (other.path, other.read_runs, other.write_runs))

    def __lt__(self, other):
        return self.path < other.path

    def __repr__(self):
        return "<InputOutputFile(path=%r, read_runs=%r, write_runs=%r)>" % (
            self.path, self.read_runs, self.write_runs)


def load_iofiles(config, runs):
    """Loads the inputs_outputs part of the configuration.

    This tests for duplicates, merge the lists of executions, and optionally
    loads from the runs for reprozip < 0.7 compatibility.
    """
    files_list = config.get('inputs_outputs') or []

    # reprozip < 0.7 compatibility: read input_files and output_files from runs
    if 'inputs_outputs' not in config:
        for i, run in enumerate(runs):
            for rkey, wkey in (('input_files', 'read_by_runs'),
                               ('output_files', 'written_by_runs')):
                for k, p in iteritems(run.pop(rkey, {})):
                    files_list.append({'name': k,
                                       'path': p,
                                       wkey: [i]})

    files = {}  # name:str: InputOutputFile
    paths = {}  # path:PosixPath: name:str
    required_keys = set(['name', 'path'])
    optional_keys = set(['read_by_runs', 'written_by_runs'])
    uniquenames = UniqueNames()
    for i, f in enumerate(files_list):
        keys = set(f)
        if (not keys.issubset(required_keys | optional_keys) or
                not keys.issuperset(required_keys)):
            raise InvalidConfig("File #%d has invalid keys")
        name = f['name']
        path = PosixPath(f['path'])
        readers = sorted(f.get('read_by_runs', []))
        writers = sorted(f.get('written_by_runs', []))
        if (
            not isinstance(readers, (tuple, list))
            or not all(isinstance(e, int) for e in readers)
        ):
            raise InvalidConfig("read_by_runs should be a list of integers")
        if (
            not isinstance(writers, (tuple, list))
            or not all(isinstance(e, int) for e in writers)
        ):
            raise InvalidConfig("written_by_runs should be a list of integers")
        if name in files:
            if files[name].path != path:
                old_name, name = name, uniquenames(name)
                logger.warning("File name appears multiple times: %s\n"
                               "Using name %s instead",
                               old_name, name)
        else:
            uniquenames.insert(name)
        if path in paths:
            if paths[path] == name:
                logger.warning("File appears multiple times: %s", name)
            else:
                logger.warning("Two files have the same path (but different "
                               "names): %s, %s\nUsing name %s",
                               name, paths[path], paths[path])
                name = paths[path]
            files[name].read_runs.update(readers)
            files[name].write_runs.update(writers)
        else:
            paths[path] = name
            files[name] = InputOutputFile(path, readers, writers)

    return files


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
    # Accepts versions from 0.2 to 0.8 inclusive
    elif not LooseVersion('0.2') <= ver < LooseVersion('0.9'):
        pkgname = (__package__ or __name__).split('.', 1)[0]
        raise InvalidConfig("Loading configuration file in unknown format %s; "
                            "this probably means that you should upgrade "
                            "%s" % (ver, pkgname))
    unknown_keys = keys_ - set(['pack_id', 'version', 'runs',
                                'inputs_outputs',
                                'packages', 'other_files',
                                'additional_patterns',
                                # Deprecated
                                'input_files', 'output_files'])
    if unknown_keys:
        logger.warning("Unrecognized sections in configuration: %s",
                       ', '.join(unknown_keys))

    runs = config.get('runs') or []
    packages = read_packages(config.get('packages'), File, Package)
    other_files = read_files(config.get('other_files'), File)

    inputs_outputs = load_iofiles(config, runs)

    # reprozip < 0.7 compatibility: set inputs/outputs on runs (for plugins)
    for i, run in enumerate(runs):
        run['input_files'] = dict((n, f.path)
                                  for n, f in iteritems(inputs_outputs)
                                  if i in f.read_runs)
        run['output_files'] = dict((n, f.path)
                                   for n, f in iteritems(inputs_outputs)
                                   if i in f.write_runs)

    # reprozip < 0.8 compatibility: assign IDs to runs
    for i, run in enumerate(runs):
        if run.get('id') is None:
            run['id'] = "run%d" % i

    record_usage_package(runs, packages, other_files,
                         inputs_outputs,
                         pack_id=config.get('pack_id'))

    kwargs = {'format_version': ver,
              'inputs_outputs': inputs_outputs}

    if canonical:
        if 'additional_patterns' in config:
            raise InvalidConfig("Canonical configuration file shouldn't have "
                                "additional_patterns key anymore")
    else:
        kwargs['additional_patterns'] = config.get('additional_patterns') or []

    return Config(runs, packages, other_files,
                  **kwargs)


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
                inputs_outputs=None,
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
           format='0.8',
           date=isodatetime(),
           what=("# It was generated by the packer and you shouldn't need to "
                 "edit it" if canonical
                 else "# You might want to edit this file before running the "
                 "packer\n# See 'reprozip pack -h' for help")))

        fp.write("runs:\n")
        for i, run in enumerate(runs):
            # Remove reprozip < 0.7 compatibility fields
            run = dict((k, v) for k, v in iteritems(run)
                       if k not in ('input_files', 'output_files'))
            fp.write("# Run %d\n" % i)
            fp.write(dump([run]).decode('utf-8'))
            fp.write("\n")

        fp.write("""\
# Input and output files

# Inputs are files that are only read by a run; reprounzip can replace these
# files on demand to run the experiment with custom data.
# Outputs are files that are generated by a run; reprounzip can extract these
# files from the experiment on demand, for the user to examine.
# The name field is the identifier the user will use to access these files.
inputs_outputs:""")
        for n, f in iteritems(inputs_outputs):
            fp.write("""\

- name: {name}
  path: {path}
  written_by_runs: {writers}
  read_by_runs: {readers}""".format(name=n, path=unicode_(f.path),
                                    readers=repr(f.read_runs),
                                    writers=repr(f.write_runs)))

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
additional_patterns:
# Examples:
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
    rootlogger = logging.root
    rootlogger.setLevel(min_level)
    rootlogger.addHandler(handler)

    # File logger
    if os.environ.get('REPROZIP_NO_LOGFILE', '').lower() in ('', 'false',
                                                             '0', 'off'):
        dotrpz = Path('~/.reprozip').expand_user()
        try:
            if not dotrpz.is_dir():
                dotrpz.mkdir()
            filehandler = logging.handlers.RotatingFileHandler(
                str(dotrpz / 'log'), mode='a',
                delay=False, maxBytes=400000, backupCount=5)
        except (IOError, OSError):
            logger.warning("Couldn't create log file %s", dotrpz / 'log')
        else:
            filehandler.setFormatter(formatter)
            filehandler.setLevel(file_level)
            rootlogger.addHandler(filehandler)

            filehandler.emit(logging.root.makeRecord(
                __name__.split('.', 1)[0],
                logging.INFO,
                "(log start)", 0,
                "Log opened %s %s",
                (datetime.now().strftime("%Y-%m-%d"), sys.argv),
                None))

    logging.getLogger('urllib3').setLevel(logging.INFO)


_usage_report = None


def setup_usage_report(name, version):
    """Sets up the usagestats module.
    """
    global _usage_report

    certificate_file = get_reprozip_ca_certificate()

    _usage_report = usagestats.Stats(
        '~/.reprozip/usage_stats',
        usagestats.Prompt(enable='%s usage_report --enable' % name,
                          disable='%s usage_report --disable' % name),
        os.environ.get('REPROZIP_USAGE_URL',
                       'https://stats.reprozip.org/'),
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
        stderr.write("Thank you, usage reports will be sent automatically "
                     "from now on.\n")
    else:
        _usage_report.disable_reporting()
        stderr.write("Usage reports will not be collected nor sent.\n")


def record_usage(**kwargs):
    """Records some info in the current usage report.
    """
    if _usage_report is not None:
        _usage_report.note(kwargs)


def record_usage_package(runs, packages, other_files,
                         inputs_outputs,
                         pack_id=None):
    """Records the info on some pack file into the current usage report.
    """
    if _usage_report is None:
        return
    for run in runs:
        record_usage(argv0=run['argv'][0])
    record_usage(pack_id=pack_id or '',
                 nb_packages=len(packages),
                 nb_package_files=sum(len(pkg.files)
                                      for pkg in packages),
                 packed_packages=sum(1 for pkg in packages
                                     if pkg.packfiles),
                 nb_other_files=len(other_files),
                 nb_input_outputs_files=len(inputs_outputs),
                 nb_input_files=sum(1 for f in itervalues(inputs_outputs)
                                    if f.read_runs),
                 nb_output_files=sum(1 for f in itervalues(inputs_outputs)
                                     if f.write_runs))


def submit_usage_report(**kwargs):
    """Submits the current usage report to the usagestats server.
    """
    _usage_report.submit(kwargs,
                         usagestats.OPERATING_SYSTEM,
                         usagestats.SESSION_TIME,
                         usagestats.PYTHON_VERSION)


def get_reprozip_ca_certificate():
    """Gets the ReproZip CA certificate filename.
    """
    fd, certificate_file = Path.tempfile(prefix='rpz_stats_ca_', suffix='.pem')
    with certificate_file.open('wb') as fp:
        fp.write(usage_report_ca)
    os.close(fd)
    atexit.register(os.remove, certificate_file.path)
    return certificate_file


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
-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIUXaa8P7qR4c0P51hCDIqj4GUbG/owDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIUmVwcm9aaXAwIBcNMjEwNDI5MjEwNTUzWhgPMjEyMTA0
MjkyMTA1NTNaMBMxETAPBgNVBAMMCFJlcHJvWmlwMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA3udPriZ8kziQE+OyLVozJFDSZTe8RLlpFsu/ZQjSnIh1
TsENMMu1lwv0GVEpT/EbtD5ORtZzwYQ7Vuh+IO4TQDhA5KvyJD2gZW8hE4txkkQd
yI5vSj0iiViA80tKB7FSDLsvz9iiDxShYHJI947gswbaLmampHIXD/Rjjs7+hmL5
RRS5NL8vCp2/2QVj5wnJupa5O2l2T1M6S/SyFcAgBMM/FhDsaA/yf4NPcOG6gFuO
b5mYz2ERSf4v9mRL+G3r6YULYGZWS5ThY0QoZ0lYt2nlthzwfftazrJ9+yfYBkoJ
K6Ug8UGtyOb5m3mK00c4wS7/wzuGgLMszkE0nE9SfwIDAQABo4GNMIGKMB0GA1Ud
DgQWBBSqrIPVnO5vkHj9ImGvOr38r4rcNjBOBgNVHSMERzBFgBSqrIPVnO5vkHj9
ImGvOr38r4rcNqEXpBUwEzERMA8GA1UEAwwIUmVwcm9aaXCCFF2mvD+6keHND+dY
QgyKo+BlGxv6MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEB
CwUAA4IBAQC2g8yX1c5JutH/qAKUVvqSwP2KBm3IyOjdbN7cvnwn0gMkwEj88j7p
dKhfO0Kfp/N4iKj1YK7PBXfrdlYhxINSbfPSVS3A9XWi8pJwiwgBfjrrACRMhBsv
HAQPnkXnaEJrQm//k8s4etT25JYaPgXS8t+dgVS0iqonYlpCB1XkE0gw1kLNCW5F
1SimUehJ5bZrJYGgo6kp44F12kPMzNHvk50Sf2p3nm2d9/BNbbJQxUBKt9n+i6Ir
xGGDWfg5F+BLKURWkoGBnnLPqkRxlkaGvk6QpIAfD1h99fTyuWUno3+NoQ7hS952
yWbmqwbavTIyG+D+kfhbGFEdRxLF5BeK
-----END CERTIFICATE-----
'''
