# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
from reprounzip.common import get_reprozip_ca_certificate
import usagestats

from reprounzip_qt import __version__ as version


_certificate_file = get_reprozip_ca_certificate()

_usage_report = usagestats.Stats(
    '~/.reprozip/usage_stats',
    usagestats.Prompt(''),
    os.environ.get('REPROZIP_USAGE_URL', 'https://stats.reprozip.org/'),
    version=('reprounzip-qt', version),
    unique_user_id=True,
    env_var='REPROZIP_USAGE_STATS',
    ssl_verify=_certificate_file.path
)


def record_usage(**kwargs):
    """Records some info in the current usage report.
    """
    if _usage_report is not None:
        _usage_report.note(kwargs)


def submit_usage_report(**kwargs):
    """Submits the current usage report to the usagestats server.
    """
    _usage_report.submit(kwargs,
                         usagestats.OPERATING_SYSTEM,
                         usagestats.SESSION_TIME,
                         usagestats.PYTHON_VERSION)
