# /path/to/virtualenv/lib/python3.8/site-packages/requests/__init__.py
# /path/to/virtualenv
#   pyvenv.cfg: has some info about environment in `key = value` format
#   share: not very much used (jupyter does), has things like manpages
#   bin: scripts from venv & entrypoints
#     activate (bash)
#     activate.ps1
#   lib
#     python3.8
#       (might be standard library files here? sometimes not)
#       site-packages
#         xxx: library
#         xxx-1.2.3.dist-info: metadata for library, might not match importname
#           RECORD: contains list of files
#           METADATA: contains name & version as well as other metadata
#         xxx.egg-link: location of library installed in 'develop' mode
#         yyy.pth: additional paths to add to sys.path, or Python code

# C:\path\to\virtualenv
#   pyvenv.cfg
#   Scripts
#     activate (bash)
#     activate.bat
#     Activate.ps1
#   Lib
#     site-packages
#       ...
#   Include

import logging
from pathlib import Path
import re

from reprozip_core.common import PackageEnvironment, Package


logger = logging.getLogger(__name__)


_re_pythonver = re.compile(r'^python[0-9]+\.[0-9]+$')


_re_record = re.compile(br'^([^,]+),([a-z0-9]{3,8}=[^,]+)?,([0-9]*)$')


def read_record(path):
    """Get the list of provided directories from dist-info/RECORD.
    """
    with path.open('rb') as fp:
        lines = fp.read().splitlines()
    top_level = set()
    for line in lines:
        m = _re_record.match(line)
        if m is None:
            logger.warning("Invalid entry in %s: %r", path, line)
            continue
        top = Path(m.group(1).decode('utf-8', 'surrogateescape')).parts[0]
        if top.endswith('.dist-info'):
            continue
        if top == '__pycache__' or top.endswith('.pyc'):
            continue
        top_level.add(top)
    return top_level


def read_metadata(path):
    """Get the name and version from dist-info/METADATA.
    """
    name = version = None
    with path.open() as fp:
        for line in fp:
            line = line.strip()
            if not line:
                break
            if line.startswith('Name:'):
                name = line[5:].strip()
            elif line.startswith('Version:'):
                version = line[8:].strip()
    return name, version


class PythonManager(object):
    def __init__(self):
        self.package_envs = []

    def search_for_files(self, files):
        # Find environments
        env_files = {}
        for f in files:
            parts = f.path.parts
            try:
                idx = parts.index('site-packages')
            except ValueError:
                continue
            if idx < 2:
                # Probably not a virtualenv
                continue
            if idx + 1 == len(parts):
                continue
            if parts[idx - 1].lower() == 'lib':
                env = Path(*parts[:idx - 1])
                site_packages = Path(*parts[:idx + 1])
                path = Path(*parts[idx + 1:])
            elif (
                _re_pythonver.match(parts[idx - 1])
                and parts[idx - 2] == 'lib'
            ):
                env = Path(*parts[:idx - 2])
                site_packages = Path(*parts[:idx + 1])
                path = Path(*parts[idx + 1:])
            else:
                continue
            env_files.setdefault(env, (site_packages, set()))[1].add((path, f))

        # Recognize packages to create Package and PackageEnvironment objects
        environments = []
        for env, (site_packages, files) in env_files.items():
            # Load all dist-info folders
            dists = {}
            packages = {}
            for dist_info in site_packages.glob('*.dist-info'):
                # Read files provided by the package
                if not (dist_info / 'RECORD').exists():
                    logger.warning(
                        "Missing dist-info file: %s",
                        dist_info / 'RECORD',
                    )
                    continue
                top_level = read_record(dist_info / 'RECORD')

                # Read METADATA
                if not (dist_info / 'METADATA').exists():
                    logger.warning(
                        "Missing dist-info file: %s",
                        dist_info / 'METADATA',
                    )
                    continue
                pkg_name, pkg_version = read_metadata(dist_info / 'METADATA')

                # Create Package
                if not pkg_name:
                    continue
                package = Package(pkg_name, pkg_version)
                for name in top_level:
                    dists[name] = package

            # Assign files to packages
            for path, f in files:
                try:
                    package = dists[path.parts[0]]
                except KeyError:
                    continue
                package.files.append(f)
                # Add the package to the set of used packages
                packages[package.name] = package

            environments.append(PackageEnvironment(
                'python-pip',
                env,
                sorted(packages.values(), key=lambda pkg: pkg.name),
            ))

        self.package_envs = environments
