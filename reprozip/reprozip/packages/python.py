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


class PythonManager(object):
    def __init__(self):
        self.package_envs = []
        self.unknown_files = set()

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
                # Read top_level.txt
                if not (dist_info / 'top_level.txt').exists():
                    logger.warning(
                        "Missing dist-info file: %s",
                        dist_info / 'top_level.txt',
                    )
                    continue
                with (dist_info / 'top_level.txt').open() as fp:
                    top_level = fp.read().splitlines()
                top_level = [line.strip() for line in top_level]
                top_level = [line for line in top_level if line]

                # Read METADATA
                package_name = package_version = None
                with (dist_info / 'METADATA').open() as fp:
                    for line in fp:
                        line = line.strip()
                        if not line:
                            break
                        if line.startswith('Name:'):
                            package_name = line[5:].strip()
                        elif line.startswith('Version:'):
                            package_version = line[8:].strip()

                # Create Package
                if not package_name:
                    continue
                package = Package(package_name, package_version)
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

        self.unknown_files = files
        self.package_envs = environments
