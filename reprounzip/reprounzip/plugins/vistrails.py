# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""VisTrails runner for reprounzip.

This file provides the --vistrails option that builds a VisTrails pipeline
alongside an unpacked experiment. Although you don't need it to generate the
.vt file, you will need VisTrails if you want to run it.

See http://www.vistrails.org/
"""

from __future__ import unicode_literals

import argparse
from datetime import datetime
import logging
import os
from reprounzip import signals
from rpaths import Path
import sys
import zipfile

from reprounzip.common import load_config
from reprounzip.main import __version__ as version
from reprounzip.utils import iteritems, escape


def do_vistrails(target):
    """Create a VisTrails workflow that runs the experiment.

    This is called from signals after an experiment has been setup by any
    unpacker.
    """
    unpacker = signals.unpacker
    dot_vistrails = Path('~/.vistrails').expand_user()

    runs, packages, other_files = load_config(target / 'config.yml',
                                              canonical=True)
    input_files = set()
    output_files = set()
    for run in runs:
        for input_name, path in iteritems(run['input_files']):
            input_files.add(input_name)
        for output_name, path in iteritems(run['output_files']):
            output_files.add(output_name)

    # Writes CLTools JSON definition
    fd, cltools_module = Path.tempfile(prefix='reprounzip_',
                                       dir=dot_vistrails / 'CLTools',
                                       suffix='.clt')
    os.close(fd)
    logging.info("Writing CLTools definition %s...", cltools_module)
    with cltools_module.open('w', encoding='utf-8', newline='\n') as fp:
        fp.write('{\n'
                 '    "_comment": "This file was generated by reprounzip '
                 '%(version)s for %(unpacker)s at %(date)s",\n\n' % {
                     'unpacker': unpacker,
                     'version': version,
                     'date': datetime.now().isoformat()})
        # python -m reprounzip.plugins.vistrails
        fp.write('    "command": "%s",\n'
                 '    "args": [\n'
                 '        [\n'
                 '            "constant",\n'
                 '            "-m",\n'
                 '            "flag",\n'
                 '            {}\n'
                 '        ],\n'
                 '        [\n'
                 '            "constant",\n'
                 '            "reprounzip.plugins.vistrails",\n'
                 '            "flag",\n'
                 '            {}\n'
                 '        ],\n' % escape(sys.executable))
        # Unpacker
        fp.write('        [\n'
                 '            "constant",\n'
                 '            "%s",\n'
                 '            "flag",\n'
                 '            {}\n'
                 '        ],\n' % unpacker)
        # Target directory
        fp.write('        [\n'
                 '            "constant",\n'
                 '            "%s",\n'
                 '            "flag",\n'
                 '            {}\n'
                 '        ]%s\n' % (
                     escape(str(target)),
                     ',' if input_files or output_files else ''))
        # Input files
        for i, input_name in enumerate(input_files):
            comma = ',' if i + 1 < len(input_files) or output_files else ''
            fp.write('        [\n'
                     '            "input",\n'
                     '            "input %(name)s",\n'
                     '            "file",\n'
                     '            {\n'
                     '                "flag": "--input-file",\n'
                     '                "prefix": "%(name)s:"\n'
                     '            }\n'
                     '        ]%(comma)s\n' % {
                         'name': escape(input_name),
                         'comma': comma})
        # Output files
        for i, output_name in enumerate(output_files):
            comma = ',' if i + 1 < len(output_files) else ''
            fp.write('        [\n'
                     '            "output",\n'
                     '            "output %(name)s",\n'
                     '            "file",\n'
                     '            {\n'
                     '                "flag": "--output-file",\n'
                     '                "prefix": "%(name)s:"\n'
                     '            }\n'
                     '        ]%(comma)s\n' % {
                         'name': escape(output_name),
                         'comma': comma})

        fp.write('    ],\n'
                 '    "stdout": [\n'
                 '        "stdout",\n'
                 '        "file",\n'
                 '        {}\n'
                 '    ]\n'
                 '}\n')

    # Writes VisTrails workflow
    vistrail = target / 'vistrails.vt'
    logging.info("Writing VisTrails workflow %s..." % vistrail)
    vtdir = Path.tempdir(prefix='reprounzip_vistrails_')
    try:
        with vtdir.open('w', 'vistrail', encoding='utf-8', newline='\n') as fp:
            fp.write('todo\n%s\n' % cltools_module)
            # TODO : write XML vistrail

        with vistrail.open('wb') as fp:
            z = zipfile.ZipFile(fp, 'w')
            with vtdir.in_dir():
                for path in Path('.').recursedir():
                    z.write(str(path))
            z.close()
    finally:
        vtdir.rmtree()


def setup_vistrails():
    """Setup the plugin.
    """
    signals.post_setup.subscribe(do_vistrails)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    parser.add_argument('unpacker')
    parser.add_argument('--input-file', action='append', default=[])
    parser.add_argument('--output-file', action='append', default=[])

    args = parser.parse_args()

    # TODO: Actually call reprounzip