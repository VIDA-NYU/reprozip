# Copyright (C) 2014-2015 New York University
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
import base64
from datetime import datetime
import hashlib
import logging
import os
from rpaths import Path
import sqlite3
import subprocess
import sys
import tarfile
import zipfile

from reprounzip.common import load_config, setup_logging, record_usage, \
    FILE_READ, FILE_WRITE
from reprounzip.main import __version__ as version
from reprounzip import signals
from reprounzip.unpackers.common import shell_escape
from reprounzip.utils import PY3, izip, iteritems, itervalues, escape


class SHA1(object):
    def __init__(self, arg=b''):
        self._hash = hashlib.sha1()
        if arg:
            self.update(arg)

    def update(self, arg):
        if not isinstance(arg, bytes):
            arg = arg.encode('ascii')
        self._hash.update(arg)

    def digest(self):
        """Returns the message digest as binary (type bytes).
        """
        return self._hash.digest()

    def hexdigest(self):
        """Returns the message digest as hexadecimal (type str).
        """
        return self._hash.hexdigest()


def escape_xml(s):
    """Escapes for XML.
    """
    return s.replace('&', '&amp;').replace('"', '&quot;')


def hash_experiment_run(run):
    """Generates a unique id from a single run of an experiment.

    This is used to name the CLTools modules.
    """
    h = SHA1()
    for input_name in sorted(run['input_files']):  # bad
        h.update('input %s\n' % input_name)
    for output_name in sorted(run['output_files']):  # bad
        h.update('output %s\n' % output_name)
    return base64.b64encode(h.digest(), b'@$')


def do_vistrails(target, pack=None, **kwargs):
    """Create a VisTrails workflow that runs the experiment.

    This is called from signals after an experiment has been setup by any
    unpacker.
    """
    record_usage(do_vistrails=True)
    unpacker = signals.unpacker
    dot_vistrails = Path('~/.vistrails').expand_user()

    config = load_config(target / 'config.yml', canonical=True)

    # Load configuration file
    tar = tarfile.open(str(pack), 'r:*')
    member = tar.getmember('METADATA/trace.sqlite3')
    member.name = 'trace.sqlite3'
    tmp = Path.tempdir('.sqlite3', 'rpuz_vt_')
    try:
        tar.extract(member, str(tmp))
        database = tmp / 'trace.sqlite3'
        # On PY3, connect() only accepts unicode
        if PY3:
            conn = sqlite3.connect(str(database))
        else:
            conn = sqlite3.connect(database.path)
        conn.row_factory = sqlite3.Row

        query_files = (set(itervalues(config.input_files)) |
                       set(itervalues(config.output_files)))

        # Apologies for this
        files_placeholders = ', '.join(['?'] * len(query_files))
        query = '''
                SELECT id AS p_id, NULL AS name, NULL as mode, timestamp
                FROM processes
                WHERE parent IS NULL
                UNION ALL
                SELECT NULL AS p_id, name, mode, timestamp
                FROM (
                    SELECT name, mode, timestamp
                    FROM opened_files
                    UNION ALL
                    SELECT name, {read} AS mode, timestamp
                    FROM executed_files
                )
                WHERE name in ({set})
                ORDER BY timestamp
                '''.format(read=FILE_READ,
                           set=files_placeholders)
        cur = conn.cursor()
        rows = cur.execute(query, [str(f) for f in query_files])

        inputs, outputs = [], []
        cur_inputs, cur_outputs = set(), set()
        row = next(rows)
        assert row[0] is not None
        for r_p_id, r_file, r_mode, r_timestamp in rows:
            # New process
            if r_p_id is not None:
                inputs.append(cur_inputs)
                outputs.append(cur_outputs)
            # File for current process
            else:
                if r_mode == FILE_READ:
                    cur_inputs.add(r_file)
                elif r_mode == FILE_WRITE:
                    cur_outputs.add(r_file)
        inputs.append(cur_inputs)
        outputs.append(cur_outputs)
        conn.close()

        if len(inputs) != len(config.runs):
            logging.error("Found %d runs in trace database, and %d runs in "
                          "configuration file. What is going on?",
                          len(inputs), len(config.runs))
            if len(inputs) < len(config.runs):
                n = len(config.runs) - len(inputs)
                fill = [set()] * n
                inputs += fill
                outputs += fill
    finally:
        tmp.rmtree()

    for i, (run, input_files, output_files) in enumerate(izip(
            config.runs, inputs, outputs)):
        module_name = write_cltools_module(run, config, dot_vistrails,
                                           input_files, output_files)

        # Writes VisTrails workflow
        bundle = target / 'vistrails.vt'
        logging.info("Writing VisTrails workflow %s...", bundle)
        vtdir = Path.tempdir(prefix='reprounzip_vistrails_')
        try:
            with vtdir.open('w', 'vistrail',
                            encoding='utf-8', newline='\n') as fp:
                vistrail = VISTRAILS_TEMPLATE
                cmdline = ' '.join(shell_escape(arg)
                                   for arg in run['argv'])
                vistrail = vistrail.format(
                        date='2014-11-12 15:31:18',
                        unpacker=unpacker,
                        directory=escape_xml(str(target.absolute())),
                        cmdline=escape_xml(cmdline),
                        module_name=module_name,
                        run=i)
                fp.write(vistrail)

            with bundle.open('wb') as fp:
                z = zipfile.ZipFile(fp, 'w')
                with vtdir.in_dir():
                    for path in Path('.').recursedir():
                        z.write(str(path))
                z.close()
        finally:
            vtdir.rmtree()


def write_cltools_module(run, config, dot_vistrails,
                         used_inputs, used_outputs):
    module_name = 'reprounzip_%s' % hash_experiment_run(run)[:7]

    # Writes CLTools JSON definition
    (dot_vistrails / 'CLTools').mkdir(parents=True)
    cltools_module = (dot_vistrails / 'CLTools' / module_name) + '.clt'
    logging.info("Writing CLTools definition %s...", cltools_module)
    with cltools_module.open('w', encoding='utf-8', newline='\n') as fp:
        fp.write('{\n'
                 '    "_comment": "This file was generated by reprounzip '
                 '%(version)s at %(date)s",\n\n' % {
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
                 '            "input",\n'
                 '            "unpacker",\n'
                 '            "string",\n'
                 '            {}\n'
                 '        ],\n')
        # Target directory
        fp.write('        [\n'
                 '            "input",\n'
                 '            "directory",\n'
                 '            "string",\n'
                 '            {}\n'
                 '        ],\n')
        # Run number
        fp.write('        [\n'
                 '            "input",\n'
                 '            "run",\n'
                 '            "string",\n'
                 '            {}\n'
                 '        ],\n')
        # Input files
        for i, (name, path) in enumerate(iteritems(config.input_files)):
            fp.write('        [\n'
                     '            "input",\n'
                     '            "input %(name)s",\n'
                     '            "file",\n'
                     '            {\n'
                     '                "flag": "--input-file",\n' % {
                         'name': escape(name)})
            if path in used_inputs:
                fp.write('                "required": true,\n')
            fp.write('                "prefix": "%(name)s:"\n'
                     '            }\n'
                     '        ],\n' % {'name': escape(name)})
        # Output files
        for i, (name, path) in enumerate(iteritems(config.output_files)):
            fp.write('        [\n'
                     '            "output",\n'
                     '            "output %(name)s",\n'
                     '            "file",\n'
                     '            {\n'
                     '                "flag": "--output-file",\n' % {
                         'name': escape(name)})
            if path in used_outputs:
                fp.write('                "required": true,\n')
            fp.write('                "prefix": "%(name)s:"\n'
                     '            }\n'
                     '        ],\n' % {'name': escape(name)})
        # Command-line
        fp.write('        [\n'
                 '            "input",\n'
                 '            "cmdline",\n'
                 '            "string",\n'
                 '            {\n'
                 '                "flag": "--cmdline"\n'
                 '            }\n'
                 '        ]\n'
                 '    ],\n')
        # Use "std file processing" since VisTrails <=2.1.4 has a bug without
        # this (also, it's inefficient)
        fp.write('    "options": {\n'
                 '        "std_using_files": ""\n'
                 '    },\n')
        # Makes the module check for errors
        fp.write('    "return_code": 0,\n')
        # Enable 'stdout' port
        fp.write('    "stdout": [\n'
                 '        "stdout",\n'
                 '        "file",\n'
                 '        {}\n'
                 '    ]\n'
                 '}\n')

    return module_name


def setup_vistrails():
    """Setup the plugin.
    """
    signals.post_setup.subscribe(do_vistrails)


def run_from_vistrails():
    setup_logging('REPROUNZIP-VISTRAILS', logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('unpacker')
    parser.add_argument('directory')
    parser.add_argument('run')
    parser.add_argument('--input-file', action='append', default=[])
    parser.add_argument('--output-file', action='append', default=[])
    parser.add_argument('--cmdline', action='store')

    args = parser.parse_args()

    runs, packages, other_files = load_config(
            Path(args.directory) / 'config.yml',
            canonical=True)
    run = runs[int(args.run)]

    python = sys.executable
    rpuz = [python, '-m', 'reprounzip.main', args.unpacker]

    os.environ['REPROUNZIP_NON_INTERACTIVE'] = 'y'

    def cmd(lst, add=None):
        if add:
            logging.info("cmd: %s %s", ' '.join(lst), add)
            string = ' '.join(shell_escape(a) for a in (rpuz + lst))
            string += ' ' + add
            subprocess.check_call(string, shell=True,
                                  cwd=args.directory)
        else:
            logging.info("cmd: %s", ' '.join(lst))
            subprocess.check_call(rpuz + lst,
                                  cwd=args.directory)

    logging.info("reprounzip-vistrails calling reprounzip; dir=%s",
                 args.directory)

    # Parses input files from the command-line
    upload_command = []
    seen_input_names = set()
    for input_file in args.input_file:
        input_name, filename = input_file.split(':', 1)
        upload_command.append('%s:%s' % (filename, input_name))
        seen_input_names.add(input_name)

    # Resets the input files that were not given
    for input_name in run['input_files']:  # bad
        if input_name not in seen_input_names:
            upload_command.append(':%s' % input_name)

    # Runs the command
    cmd(['upload', '.'] + upload_command)

    # Runs the experiment
    if args.cmdline:
        cmd(['run', '.', '--cmdline'], add=args.cmdline)
    else:
        cmd(['run', '.'])

    # Gets output files
    for output_file in args.output_file:
        output_name, filename = output_file.split(':', 1)
        cmd(['download', '.',
             '%s:%s' % (output_name, filename)])


# This should be package_data, however it doesn't work with namespace packages
VISTRAILS_TEMPLATE = (
    '<vistrail id="" name="" version="1.0.4" xmlns:xsi="http://www.w3.org/2001'
    '/XMLSchema-instance" xsi:schemaLocation="http://www.vistrails.org/vistrai'
    'l.xsd">\n'
    '  <action date="{date}" id="1" prevId="0" session="0" user="ReproUnzip">'
    '\n'
    '    <add id="0" objectId="0" parentObjId="" parentObjType="" what="module'
    '">\n'
    '      <module cache="1" id="0" name="{module_name}" namespace="" package='
    '"org.vistrails.vistrails.cltools" version="0.1.2" />\n'
    '    </add>\n'
    '    <add id="1" objectId="0" parentObjId="0" parentObjType="module" what='
    '"location">\n'
    '      <location id="0" x="0.0" y="0.0" />\n'
    '    </add>\n'
    '    <add id="2" objectId="0" parentObjId="0" parentObjType="module" what='
    '"function">\n'
    '      <function id="0" name="directory" pos="0" />\n'
    '    </add>\n'
    '    <add id="3" objectId="0" parentObjId="0" parentObjType="function" wha'
    't="parameter">\n'
    '      <parameter alias="" id="0" name="&lt;no description&gt;" pos="0" ty'
    'pe="org.vistrails.vistrails.basic:String" val="{directory}" />\n'
    '    </add>\n'
    '    <add id="4" objectId="1" parentObjId="0" parentObjType="module" what='
    '"function">\n'
    '      <function id="1" name="unpacker" pos="1" />\n'
    '    </add>\n'
    '    <add id="5" objectId="1" parentObjId="1" parentObjType="function" wha'
    't="parameter">\n'
    '      <parameter alias="" id="1" name="&lt;no description&gt;" pos="0" ty'
    'pe="org.vistrails.vistrails.basic:String" val="{unpacker}" />\n'
    '    </add>\n'
    '    <add id="6" objectId="2" parentObjId="0" parentObjType="module" what='
    '"function">\n'
    '      <function id="2" name="run" pos="1" />\n'
    '    </add>\n'
    '    <add id="7" objectId="2" parentObjId="2" parentObjType="function" wha'
    't="parameter">\n'
    '      <parameter alias="" id="2" name="&lt;no description&gt;" pos="0" ty'
    'pe="org.vistrails.vistrails.basic:String" val="{run}" />\n'
    '    </add>\n'
    '    <add id="6" objectId="3" parentObjId="0" parentObjType="module" what='
    '"function">\n'
    '      <function id="3" name="cmdline" pos="1" />\n'
    '    </add>\n'
    '    <add id="7" objectId="3" parentObjId="3" parentObjType="function" wha'
    't="parameter">\n'
    '      <parameter alias="" id="3" name="&lt;no description&gt;" pos="0" ty'
    'pe="org.vistrails.vistrails.basic:String" val="{cmdline}" />\n'
    '    </add>\n'
    '  </action>\n'
    '</vistrail>\n')


if __name__ == '__main__':
    run_from_vistrails()
