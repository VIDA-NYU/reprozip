# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Common functions between reprozip and reprounzip.

This module contains functions that are specific to the reprozip software and
its data formats, but that are shared between the reprozip and reprounzip
packages. Because the packages can be installed separately, these functions are
in a separate module which they both depend on.

# Pack format history

* 1: used by reprozip 0.2 through 0.7. Single tar.gz file, metadata under
  `METADATA/`, data under `DATA/`
* 2: pack is usually not compressed, metadata under `METADATA/`, data in
  another `DATA.tar.gz` (files inside it still have the `DATA/` prefix for
  ease-of-use in unpackers)

# Pack metadata history

* 0.2: used by reprozip 0.2
* 0.2.1:
  - config: comments directories as such in config
  - trace database: adds `executed_files.workingdir`, adds `processes.exitcode`
  - data: packs dynamic linkers
* 0.3:
  - config: don't list missing (unpacked) files in config
  - trace database: adds `opened_files.is_directory`
* 0.3.1: no change
* 0.3.2: no change
* 0.4:
  - config: adds `input_files`, `output_files`, lists parent directories
* 0.4.1: no change
* 0.5: no change
* 0.6: no change
* 0.7:
  - moves `input_files` and `output_files` from run to global scope
  - adds `processes.is_thread` column to trace database
* 0.8: adds `id` field to run
* 1.0: no change, ReproZip 1.0 actually uses format 0.8
* 1.1:
  - adds `processes.exit_timestamp`
  - adds `processes.cpu_time`
* 2.0:
  - change packages from list of packages to list of environments
"""

import contextlib
import copy
from datetime import datetime
from distutils.version import LooseVersion
import functools
import gzip
import json
import logging
import logging.handlers
import os
from pathlib import Path, PurePosixPath
import pkg_resources
import shutil
import sys
import tarfile
import tempfile
import usagestats
import yaml

from .utils import UniqueNames, escape, yaml_dumps, optional_return_type, \
    isodatetime, hsize, join_root


logger = logging.getLogger('reprozip_core')


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
        self.path = Path(path)
        self.size = size

    def __eq__(self, other):
        return (isinstance(other, File) and
                self.path == other.path)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.path)

    def __repr__(self):
        return '<File %r>' % self.path

    @classmethod
    def from_local(cls, path):
        size = None
        comment = None
        if path.exists():
            if path.is_symlink():
                target = Path(os.readlink(path))
                target = (path.parent / target).absolute()
                comment = "Link to %s" % target
            elif path.is_dir():
                comment = "Directory"
            else:
                size = path.stat().st_size
                comment = hsize(size)
        file = cls(path, size)
        file.comment = comment
        return file


class Package(object):
    """A distribution package, containing a set of files.
    """
    def __init__(self, name, version, files=None, packfiles=True, size=None,
                 meta=None):
        self.name = name
        self.version = version
        self.files = list(files) if files is not None else []
        self.packfiles = packfiles
        self.size = size
        self.meta = meta or {}

    def __eq__(self, other):
        return (isinstance(other, Package) and
                self.name == other.name and
                self.version == other.version)

    def __ne__(self, other):
        return not self.__eq__(other)

    def add_file(self, file_):
        self.files.append(file_)

    def __repr__(self):
        return '<Package %r (%r)>' % (self.name, self.version)

    def __str__(self):
        return '%s (%s)' % (self.name, self.version)


class PackageEnvironment(object):
    """A package manager environment, containing packages.
    """
    def __init__(self, package_manager, path, packages=None):
        self.package_manager = package_manager
        self.path = path
        self.packages = packages if packages is not None else []

    def add_package(self, package):
        self.packages.append(package)

    def __str__(self):
        return '%s at %s' % (self.package_manager, self.path)


class RPZPack(object):
    """Encapsulates operations on the RPZ pack format.
    """
    def __init__(self, pack):
        self.pack = Path(pack)

        self.tar = tarfile.open(str(self.pack), 'r:*')
        f = self.tar.extractfile('METADATA/version')
        version = f.read()
        f.close()
        if version.startswith(b'REPROZIP VERSION '):
            try:
                version = int(version[17:].rstrip())
            except ValueError:
                version = None
            if version in (1, 2):
                self.version = version
                self.data_prefix = PurePosixPath('DATA')
            else:
                raise ValueError(
                    "Unknown format version %r (maybe you should upgrade "
                    "reprounzip? I only know versions 1 and 2" % version)
        else:
            raise ValueError("File doesn't appear to be a RPZ pack")

        if self.version == 1:
            self.data = self.tar
        elif version == 2:
            self.data = tarfile.open(
                fileobj=self.tar.extractfile('DATA.tar.gz'),
                mode='r:*')
        else:
            assert False

    def remove_data_prefix(self, path):
        if not isinstance(path, PurePosixPath):
            path = PurePosixPath(path)
        components = path.parts[1:]
        if not components:
            return path.__class__('')
        return path.__class__(*components)

    def open_config(self):
        """Gets the configuration file.
        """
        return self.tar.extractfile('METADATA/config.yml')

    def extract_config(self, target):
        """Extracts the config to the specified path.

        It is up to the caller to remove that file once done.
        """
        self._extract_file(self.tar.getmember('METADATA/config.yml'),
                           target)

    def _extract_file(self, member, target):
        member = copy.copy(member)
        member.name = str(target.parts[-1])
        self.tar.extract(member,
                         path=str(Path.cwd() / target.parent))
        target.chmod(0o644)
        assert target.is_file()

    def _extract_file_gz(self, member, target):
        f_in = self.tar.extractfile(member)
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

    @contextlib.contextmanager
    def with_config(self):
        """Context manager that extracts the config to  a temporary file.
        """
        fd, tmp = tempfile.mkstemp(prefix='reprounzip_')
        tmp = Path(tmp)
        os.close(fd)
        self.extract_config(tmp)
        yield tmp
        tmp.unlink()

    def extract_trace(self, target):
        """Extracts the trace database to the specified path.

        It is up to the caller to remove that file once done.
        """
        target = Path(target)
        if self.version == 1:
            member = self.tar.getmember('METADATA/trace.sqlite3')
            self._extract_file(member, target)
        elif self.version == 2:
            try:
                member = self.tar.getmember('METADATA/trace.sqlite3.gz')
            except KeyError:
                pass
            else:
                self._extract_file_gz(member, target)
                return
            member = self.tar.getmember('METADATA/trace.sqlite3')
            self._extract_file(member, target)
        else:
            assert False

    @contextlib.contextmanager
    def with_trace(self):
        """Context manager that extracts the trace database to a temporary file.
        """
        fd, tmp = tempfile.mkstemp(prefix='reprounzip_')
        tmp = Path(tmp)
        os.close(fd)
        self.extract_trace(tmp)
        yield tmp
        tmp.unlink()

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
        return set(PurePosixPath(m.name[4:])
                   for m in self.data.getmembers()
                   if m.name.startswith('DATA/'))

    def get_data(self, path):
        """Returns a tarfile.TarInfo object for the data path.

        Raises KeyError if no such path exists.
        """
        path = PurePosixPath(path)
        path = join_root(PurePosixPath('DATA'), path)
        return copy.copy(self.data.getmember(path))

    def extract_data(self, root, members):
        """Extracts the given members from the data tarball.

        The members must come from get_data().
        """
        self.data.extractall(str(root), members)

    def copy_data_tar(self, target):
        """Copies the file in which the data lies to the specified destination.
        """
        if self.version == 1:
            shutil.copyfile(self.pack, target)
        elif self.version == 2:
            with target.open('wb') as fp:
                data = self.tar.extractfile('DATA.tar.gz')
                shutil.copyfileobj(data, fp)
                data.close()

    def close(self):
        if self.data is not self.tar:
            self.data.close()
        self.tar.close()
        self.data = self.tar = None


class InvalidConfig(ValueError):
    """Configuration file is invalid.
    """


def read_files(files):
    if files is None:
        return []
    return [File(PurePosixPath(f)) for f in files]


def read_packages(packages):
    if packages is None:
        return []
    new_pkgs = []
    for pkg in packages:
        pkg['files'] = read_files(pkg['files'])
        new_pkgs.append(Package(**pkg))
    return new_pkgs


def read_package_environments(
    package_envs,
):
    if package_envs is None:
        return []
    new_environments = []
    for env in package_envs:
        env['packages'] = read_packages(env['packages'])
        new_environments.append(PackageEnvironment(**env))
    return new_environments


Config = optional_return_type(['runs', 'package_envs', 'other_files'],
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
                for k, p in run.pop(rkey, {}).items():
                    files_list.append({'name': k,
                                       'path': p,
                                       wkey: [i]})

    files = {}  # name:str: InputOutputFile
    paths = {}  # path:PurePosixPath: name:str
    required_keys = {'name', 'path'}
    optional_keys = {'read_by_runs', 'written_by_runs'}
    uniquenames = UniqueNames()
    for i, f in enumerate(files_list):
        keys = set(f)
        if (not keys.issubset(required_keys | optional_keys) or
                not keys.issuperset(required_keys)):
            raise InvalidConfig("File #%d has invalid keys")
        name = f['name']
        if name.startswith('/'):
            logger.warning("File name looks like a path: %s, prefixing with "
                           ".", name)
            name = '.%s' % name
        path = PurePosixPath(f['path'])
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


def _bytes_to_surrogates(container):
    if isinstance(container, dict):
        iterator = container.items()
    elif isinstance(container, list):
        iterator = enumerate(container)
    else:
        raise TypeError

    for k, v in iterator:
        if isinstance(v, bytes):
            container[k] = v.decode('utf-8', 'surrogateescape')
        elif isinstance(v, (list, dict)):
            _bytes_to_surrogates(v)


def load_config(filename, canonical):
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

    # Turn bytes values into Python 3 str values
    _bytes_to_surrogates(config)

    ver = LooseVersion(config['version'])

    keys_ = set(config)
    if 'version' not in keys_:
        raise InvalidConfig("Missing version")
    # Accepts versions from 0.2 to 1.1 inclusive
    elif not LooseVersion('0.2') <= ver < LooseVersion('2.1'):
        raise InvalidConfig("Loading configuration file in unknown format %s; "
                            "this probably means that you should upgrade "
                            "reprozip-core" % ver)
    unknown_keys = keys_ - {'pack_id', 'version', 'runs',
                            'inputs_outputs',
                            'packages', 'other_files',
                            'additional_patterns'}
    if unknown_keys:
        logger.warning("Unrecognized sections in configuration: %s",
                       ', '.join(unknown_keys))

    runs = config.get('runs') or []
    if ver < LooseVersion('2.0'):
        # Read the old flat 'packages' section, guess the package manager
        packages = read_packages(config.get('packages'))
        dist = config['runs'][0]['distribution'][0].lower()
        if dist in ('debian', 'ubuntu'):
            package_manager = 'dpkg'
        elif (
            dist in ('centos', 'centos linux', 'fedora', 'scientific linux')
            or dist.startswith('red hat')
        ):
            package_manager = 'rpm'
        else:
            raise InvalidConfig("Unknown package manager listed")
        package_envs = [PackageEnvironment(package_manager, '/', packages)]
    else:
        package_envs = read_package_environments(config.get('packages'))
    other_files = read_files(config.get('other_files'))

    inputs_outputs = load_iofiles(config, runs)

    # reprozip < 0.8 compatibility: assign IDs to runs
    for i, run in enumerate(runs):
        if run.get('id') is None:
            run['id'] = "run%d" % i

    record_usage_package(runs, package_envs, other_files,
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

    return Config(runs, package_envs, other_files,
                  **kwargs)


def write_file(fp, fi, indent=0):
    fp.write("%s  - \"%s\"%s\n" % (
             "  " * indent,
             escape(str(fi.path)),
             ' # %s' % fi.comment if fi.comment is not None else ''))


def write_package(fp, pkg, indent=3):
    indent_str = "  " * indent
    fp.write("%s- name: \"%s\"\n" % (indent_str, escape(pkg.name)))
    fp.write("%s  version: \"%s\"\n" % (indent_str, escape(pkg.version)))
    if pkg.size is not None:
        fp.write("%s  size: %d\n" % (indent_str, pkg.size))
    fp.write("%s  packfiles: %s\n" % (
        indent_str,
        'true' if pkg.packfiles else 'false',
    ))
    if pkg.meta:
        fp.write("%s  meta: %s\n" % (indent_str, json.dumps(pkg.meta),))
    fp.write("%s  files:\n"
             "%s    # Total files used: %s\n" % (
                 indent_str, indent_str,
                 hsize(sum(fi.size
                           for fi in pkg.files
                           if fi.size is not None))))
    if pkg.size is not None:
        fp.write("%s    # Installed package size: %s\n" % (
                 indent_str, hsize(pkg.size)))
    for fi in sorted(pkg.files, key=lambda fi_: fi_.path):
        write_file(fp, fi, indent + 1)


def save_config(filename, runs, package_envs, other_files, reprozip_version,
                inputs_outputs=None,
                canonical=False, pack_id=None):
    """Saves the configuration to a YAML file.

    `canonical` indicates whether this is a canonical configuration file
    (no ``additional_patterns`` section).
    """
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
           format='2.0',
           date=isodatetime(),
           what=("# It was generated by the packer and you shouldn't need to "
                 "edit it" if canonical
                 else "# You might want to edit this file before running the "
                 "packer\n# See 'reprozip pack -h' for help")))

        fp.write("runs:\n")
        for i, run in enumerate(runs):
            fp.write("# Run %d\n" % i)
            fp.write(yaml_dumps([run], initial_indent=1))
            fp.write("\n")

        fp.write("""\
# Input and output files

# Inputs are files that are only read by a run; reprounzip can replace these
# files on demand to run the experiment with custom data.
# Outputs are files that are generated by a run; reprounzip can extract these
# files from the experiment on demand, for the user to examine.
# The name field is the identifier the user will use to access these files.
inputs_outputs:""")
        for n, f in sorted(inputs_outputs.items()):
            fp.write("""\

  - name: {name}
    path: {path}
    written_by_runs: {writers}
    read_by_runs: {readers}""".format(name=n, path=str(f.path),
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
        for package_env in package_envs:
            fp.write("""\
  - package_manager: {manager}
    environment: {path}
    packages:
""".format(
                manager=package_env.package_manager,
                path=package_env.path,
            ))
            for pkg in sorted(package_env.packages, key=lambda p: p.name):
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
# Example:
#   - /etc/apache2/**  # Everything under apache2/
#   - /var/log/apache2/*.log  # Log files directly under apache2/
#   - /var/lib/lxc/*/rootfs/home/**/*.py  # All Python files of all users in
#     # that container
""")


def create_trace_schema(conn):
    """Create the trace database schema on a given SQLite3 connection.
    """
    sql = [
        '''
        CREATE TABLE processes(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            parent INTEGER,
            timestamp INTEGER NOT NULL,
            exit_timestamp INTEGER,
            cpu_time INTEGER,
            is_thread BOOLEAN NOT NULL,
            exitcode INTEGER
            );
        ''',
        '''
        CREATE INDEX proc_parent_idx ON processes(parent);
        ''',
        '''
        CREATE TABLE opened_files(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            mode INTEGER NOT NULL,
            is_directory BOOLEAN NOT NULL,
            process INTEGER NOT NULL
            );
        ''',
        '''
        CREATE INDEX open_proc_idx ON opened_files(process);
        ''',
        '''
        CREATE TABLE executed_files(
            id INTEGER NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            run_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            process INTEGER NOT NULL,
            argv TEXT NOT NULL,
            envp TEXT NOT NULL,
            workingdir TEXT NOT NULL
            );
        ''',
        '''
        CREATE INDEX exec_proc_idx ON executed_files(process);
        ''',
        '''
        CREATE TABLE connections(
            id INTEGER NOT NULL PRIMARY KEY,
            run_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            process INTEGER NOT NULL,
            inbound INTEGER NOT NULL,
            family TEXT NULL,
            protocol TEXT NULL,
            address TEXT NULL
            );
        ''',
        '''
        CREATE INDEX connections_proc_idx ON connections(process);
        ''',
    ]
    for stmt in sql:
        conn.execute(stmt)


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
        dotrpz = Path('~/.reprozip').expanduser()
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
        ssl_verify=certificate_file)
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
        print("Thank you, usage reports will be sent automatically "
              "from now on.\n", file=sys.stderr)
    else:
        _usage_report.disable_reporting()
        print("Usage reports will not be collected nor sent.\n",
              file=sys.stderr)


def record_usage(**kwargs):
    """Records some info in the current usage report.
    """
    if _usage_report is not None:
        _usage_report.note(kwargs)


def record_usage_package(runs, package_envs, other_files,
                         inputs_outputs,
                         pack_id=None):
    """Records the info on some pack file into the current usage report.
    """
    if _usage_report is None:
        return
    for run in runs:
        record_usage(argv0=run['argv'][0])
    record_usage(pack_id=pack_id or '',
                 nb_environments=len(package_envs),
                 nb_packages=sum(len(env.packages) for env in package_envs),
                 nb_package_files=sum(len(pkg.files)
                                      for env in package_envs
                                      for pkg in env.packages),
                 packed_packages=sum(1
                                     for env in package_envs
                                     for pkg in env.packages
                                     if pkg.packfiles),
                 nb_other_files=len(other_files),
                 nb_input_outputs_files=len(inputs_outputs),
                 nb_input_files=sum(1 for f in inputs_outputs.values()
                                    if f.read_runs),
                 nb_output_files=sum(1 for f in inputs_outputs.values()
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
    return Path(pkg_resources.resource_filename(
        __name__.split('.', 1)[0],
        'reprozip-ca.crt',
    ))
