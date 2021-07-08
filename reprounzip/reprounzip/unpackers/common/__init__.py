# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions for unpacker plugins.

This contains functions related to shell scripts, package managers, and the
pack files.
"""

from reprozip_core.utils import join_root
from reprounzip.unpackers.common.misc import UsageError, \
    COMPAT_OK, COMPAT_NO, COMPAT_MAYBE, \
    composite_action, target_must_exist, unique_names, \
    make_unique_name, shell_escape, load_config, busybox_url, rpzsudo_binary, \
    rpztar_url, \
    FileUploader, FileDownloader, get_runs, add_environment_options, \
    parse_environment_args, fixup_environment, interruptible_call, \
    metadata_read, metadata_write, metadata_initial_iofiles, \
    metadata_update_run, parse_ports
from reprounzip.unpackers.common.packages import THIS_DISTRIBUTION, \
    PKG_NOT_INSTALLED, CantFindInstaller, select_installer


__all__ = ['THIS_DISTRIBUTION', 'PKG_NOT_INSTALLED', 'select_installer',
           'COMPAT_OK', 'COMPAT_NO', 'COMPAT_MAYBE',
           'UsageError', 'CantFindInstaller',
           'composite_action', 'target_must_exist', 'unique_names',
           'make_unique_name', 'shell_escape', 'load_config', 'busybox_url',
           'rpzsudo_binary', 'rpztar_url',
           'join_root', 'FileUploader', 'FileDownloader', 'get_runs',
           'add_environment_options', 'parse_environment_args',
           'fixup_environment', 'interruptible_call', 'metadata_read',
           'metadata_write', 'metadata_initial_iofiles', 'metadata_update_run',
           'parse_ports']
