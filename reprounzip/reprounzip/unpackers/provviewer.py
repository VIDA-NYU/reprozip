# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Prov Viewer exporter.

This exports the trace data into a format suitable for the Prov Viewer tool
(https://github.com/gems-uff/prov-viewer).

See schema: https://git.io/provviewer-xsd
"""

from __future__ import division, print_function, unicode_literals

import argparse
import logging
from distutils.version import LooseVersion
from rpaths import Path
import sqlite3
import sys

from reprounzip.common import FILE_WRITE, RPZPack, load_config
from reprounzip.unpackers.common import COMPAT_OK, COMPAT_NO, shell_escape
from reprounzip.utils import PY3, iteritems, stderr


logger = logging.getLogger('reprounzip.provviewer')


def xml_escape(s):
    """Escapes for XML.
    """
    return (("%s" % s).replace('&', '&amp;').replace('"', '&quot;')
            .replace('<', '&lg;').replace('>', '&gt;'))


def generate(target, configfile, database):
    """Go over the trace and generate the graph file.
    """
    # Reads package ownership from the configuration
    if not configfile.is_file():
        logger.critical("Configuration file does not exist!\n"
                        "Did you forget to run 'reprozip trace'?\n"
                        "If not, you might want to use --dir to specify an "
                        "alternate location.")
        sys.exit(1)

    config = load_config(configfile, canonical=False)

    has_thread_flag = config.format_version >= LooseVersion('0.7')

    if PY3:
        # On PY3, connect() only accepts unicode
        conn = sqlite3.connect(str(database))
    else:
        conn = sqlite3.connect(database.path)
    conn.row_factory = sqlite3.Row

    vertices = []
    edges = []

    # Create user entity, that initiates the runs
    vertices.append({'ID': 'user',
                     'type': 'Agent',
                     'subtype': 'User',
                     'label': 'User'})

    run = -1

    # Read processes
    cur = conn.cursor()
    rows = cur.execute(
        '''
        SELECT id, parent, timestamp, is_thread, exitcode
        FROM processes;
        ''' if has_thread_flag else '''
        SELECT id, parent, timestamp, 0 as is_thread, exitcode
        FROM processes;
        ''')
    for r_id, r_parent, r_timestamp, r_isthread, r_exitcode in rows:
        if r_parent is None:
            # Create run entity
            run += 1
            vertices.append({'ID': 'run%d' % run,
                             'type': 'Activity',
                             'subtype': 'Run',
                             'label': "Run #%d" % run,
                             'date': r_timestamp})
            # User -> run
            edges.append({'ID': 'user_run%d' % run,
                          'type': 'UserRuns',
                          'label': "User runs command",
                          'sourceID': 'user',
                          'targetID': 'run%d' % run})
            # Run -> process
            edges.append({'ID': 'run_start%d' % run,
                          'type': 'RunStarts',
                          'label': "Run #%d command",
                          'sourceID': 'run%d' % run,
                          'targetID': 'process%d' % r_id})

        # Create process entity
        vertices.append({'ID': 'process%d' % r_id,
                         'type': 'Agent',
                         'subtype': 'Thread' if r_isthread else 'Process',
                         'label': 'Process #%d' % r_id,
                         'date': r_timestamp})
        # TODO: add process end time (use master branch?)

        # Add process creation activity
        if r_parent is not None:
            # Process creation activity
            vertex = {'ID': 'fork%d' % r_id,
                      'type': 'Activity',
                      'subtype': 'Fork',
                      'label': "#%d creates %s #%d" % (
                          r_parent,
                          "thread" if r_isthread else "process",
                          r_id),
                      'date': r_timestamp}
            if has_thread_flag:
                vertex['thread'] = 'true' if r_isthread else 'false'
            vertices.append(vertex)

            # Parent -> creation
            edges.append({'ID': 'fork_p_%d' % r_id,
                          'type': 'PerformsFork',
                          'label': "Performs fork",
                          'sourceID': 'process%d' % r_parent,
                          'targetID': 'fork%d' % r_id})
            # Creation -> child
            edges.append({'ID': 'fork_c_%d' % r_id,
                          'type': 'ForkCreates',
                          'label': "Fork creates",
                          'sourceID': 'fork%d' % r_id,
                          'targetID': 'process%d' % r_id})
    cur.close()

    file2package = dict((f.path.path, pkg)
                        for pkg in config.packages
                        for f in pkg.files)
    inputs_outputs = dict((f.path.path, (bool(f.write_runs),
                                         bool(f.read_runs)))
                          for n, f in iteritems(config.inputs_outputs))

    # Read opened files
    cur = conn.cursor()
    rows = cur.execute(
        '''
        SELECT name, is_directory
        FROM opened_files
        GROUP BY name;
        ''')
    for r_name, r_directory in rows:
        # Create file entity
        vertex = {'ID': r_name,
                  'type': 'Entity',
                  'subtype': 'Directory' if r_directory else 'File',
                  'label': r_name}
        if r_name in file2package:
            vertex['package'] = file2package[r_name].name
        if r_name in inputs_outputs:
            out_, in_ = inputs_outputs[r_name]
            if in_:
                vertex['input'] = True
            if out_:
                vertex['output'] = True
        vertices.append(vertex)
    cur.close()

    # Read file opens
    cur = conn.cursor()
    rows = cur.execute(
        '''
        SELECT id, name, timestamp, mode, process
        FROM opened_files;
        ''')
    for r_id, r_name, r_timestamp, r_mode, r_process in rows:
        # Create file access activity
        vertices.append({'ID': 'access%d' % r_id,
                         'type': 'Activity',
                         'subtype': ('FileWrites' if r_mode & FILE_WRITE
                                     else 'FileReads'),
                         'label': ("File write: %s" if r_mode & FILE_WRITE
                                   else "File read: %s") % r_name,
                         'date': r_timestamp,
                         'mode': r_mode})
        # Process -> access
        edges.append({'ID': 'proc_access%d' % r_id,
                      'type': 'PerformsFileAccess',
                      'label': "Process does file access",
                      'sourceID': 'process%d' % r_process,
                      'targetID': 'access%d' % r_id})
        # Access -> file
        edges.append({'ID': 'access_file%d' % r_id,
                      'type': 'AccessFile',
                      'label': "File access touches",
                      'sourceID': 'access%d' % r_id,
                      'targetID': r_name})
    cur.close()

    # Read executions
    cur = conn.cursor()
    rows = cur.execute(
        '''
        SELECT id, name, timestamp, process, argv
        FROM executed_files;
        ''')
    for r_id, r_name, r_timestamp, r_process, r_argv in rows:
        argv = r_argv.split('\0')
        if not argv[-1]:
            argv = argv[:-1]
        cmdline = ' '.join(shell_escape(a) for a in argv)

        # Create execution activity
        vertices.append({'ID': 'exec%d' % r_id,
                         'type': 'Activity',
                         'subtype': 'ProcessExecutes',
                         'label': "Process #%d executes file %s" % (r_process,
                                                                    r_name),
                         'date': r_timestamp,
                         'cmdline': cmdline,
                         'process': r_process,
                         'file': r_name})
        # Process -> execution
        edges.append({'ID': 'proc_exec%d' % r_id,
                      'type': 'ProcessExecution',
                      'label': "Process does exec()",
                      'sourceID': 'process%d' % r_process,
                      'targetID': 'exec%d' % r_id})
        # Execution -> file
        edges.append({'ID': 'exec_file%d' % r_id,
                      'type': 'ExecutionFile',
                      'label': "Execute file",
                      'sourceID': 'exec%d' % r_id,
                      'targetID': r_name})
    cur.close()

    # Write the file from the created lists
    with target.open('w', encoding='utf-8', newline='\n') as out:
        out.write('<?xml version="1.0"?>\n\n'
                  '<provenancedata xmlns:xsi="http://www.w3.org/2001/XMLSchema'
                  '-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
                  '  <vertices>\n')

        for vertex in vertices:
            if 'date' not in vertex:
                vertex['date'] = '-1'
            tags = {}
            for k in ('ID', 'type', 'label', 'date'):
                if k not in vertex:
                    vertex.update(tags)
                    raise ValueError("Vertex is missing tag '%s': %r" % (
                                     k, vertex))
                tags[k] = vertex.pop(k)
            out.write('    <vertex>\n      ' +
                      '\n      '.join('<{k}>{v}</{k}>'.format(k=k,
                                                              v=xml_escape(v))
                                      for k, v in iteritems(tags)))
            if vertex:
                out.write('\n      <attributes>\n')
                for k, v in iteritems(vertex):
                    out.write('        <attribute>\n'
                              '          <name>{k}</name>\n'
                              '          <value>{v}</value>\n'
                              '        </attribute>\n'
                              .format(k=xml_escape(k),
                                      v=xml_escape(v)))
                out.write('      </attributes>')
            out.write('\n    </vertex>\n')
        out.write('  </vertices>\n'
                  '  <edges>\n')
        for edge in edges:
            for k in ('ID', 'type', 'label', 'sourceID', 'targetID'):
                if k not in edge:
                    raise ValueError("Edge is missing tag '%s': %r" % (
                                     k, edge))
            if 'value' not in edge:
                edge['value'] = ''
            out.write('    <edge>\n      ' +
                      '\n      '.join('<{k}>{v}</{k}>'.format(k=k,
                                                              v=xml_escape(v))
                                      for k, v in iteritems(edge)) +
                      '\n    </edge>\n')
        out.write('  </edges>\n'
                  '</provenancedata>\n')

    conn.close()


def provgraph(args):
    """provgraph subcommand.

    Reads in the trace sqlite3 database and writes out a graph in Provenance
    Viewer graph format."""
    def call_generate(args, config, trace):
        generate(Path(args.target[0]), config, trace)

    if args.pack is not None:
        rpz_pack = RPZPack(args.pack)
        with rpz_pack.with_config() as config:
            with rpz_pack.with_trace() as trace:
                call_generate(args, config, trace)
    else:
        call_generate(args,
                      Path(args.dir) / 'config.yml',
                      Path(args.dir) / 'trace.sqlite3')


def disabled_bug13676(args):
    stderr.write("Error: your version of Python, %s, is not supported\n"
                 "Versions before 2.7.3 are affected by bug 13676 and will "
                 "not be able to read\nthe trace "
                 "database\n" % sys.version.split(' ', 1)[0])
    sys.exit(1)


def setup(parser, **kwargs):
    """Generates a Prov Viewer graph from the trace data
    """

    # http://bugs.python.org/issue13676
    # This prevents repro(un)zip from reading argv and envp arrays from trace
    if sys.version_info < (2, 7, 3):
        parser.add_argument('rest_of_cmdline', nargs=argparse.REMAINDER,
                            help=argparse.SUPPRESS)
        parser.set_defaults(func=disabled_bug13676)
        return {'test_compatibility': (COMPAT_NO, "Python >2.7.3 required")}

    parser.add_argument('target', nargs=1, help="Destination DOT file")
    parser.add_argument(
        '-d', '--dir', default='.reprozip-trace',
        help="where the database and configuration file are stored (default: "
        "./.reprozip-trace)")
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to extract (defaults to reading from --dir)")
    parser.set_defaults(func=provgraph)

    return {'test_compatibility': COMPAT_OK}
