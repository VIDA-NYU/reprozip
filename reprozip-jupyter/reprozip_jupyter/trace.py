# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Trace a notebook to generate accompanying RPZ pack.
"""

from __future__ import division, print_function, unicode_literals

import argparse
from jupyter_client.launcher import launch_kernel
from jupyter_client.manager import KernelManager
from jupyter_client.managerabc import KernelManagerABC
import logging
from nbconvert.preprocessors import ExecutePreprocessor
from nbconvert.preprocessors.execute import CellExecutionError
import nbformat
import os
from rpaths import Path
import sys

from reprounzip.common import setup_logging


logger = logging.getLogger('reprozip_jupyter')


class RPZOptions(object):
    def __init__(self, verbosity=1, dir=None, identify_packages=True,
                 find_inputs_outputs=True, append=None):
        self.verbosity = verbosity
        self.dir = dir
        self.identify_packages = identify_packages
        self.find_inputs_outputs = find_inputs_outputs
        self.append = append

    def trace_command_line(self, kernel_cmd):
        cmd = ['reprozip']
        cmd.extend(['-v'] * (self.verbosity - 1))
        cmd.append('trace')
        if self.dir:
            cmd.extend(['--dir', self.dir])
        if not self.identify_packages:
            cmd.append('--dont-identify-packages')
        if not self.find_inputs_outputs:
            cmd.append('--dont-find-inputs-outputs')
        if self.append:
            cmd.append('--continue')
        else:
            cmd.append('--overwrite')
        cmd.extend(kernel_cmd)
        return cmd

    def config_file(self):
        if self.dir:
            return Path(self.dir) / 'config.yml'
        else:
            return Path('.reprozip-trace/config.yml')


class RPZKernelManager(KernelManager):
    rpz_options = None

    def _launch_kernel(self, kernel_cmd, **kw):
        cmd = self.rpz_options.trace_command_line(kernel_cmd)

        logger.info("Kernel requested, connection file: %s",
                    self.connection_file)
        logger.info("Executing: %r", cmd)
        return launch_kernel(cmd, **kw)

    def finish_shutdown(self, *args, **kwargs):
        kwargs['waittime'] = 600
        super(RPZKernelManager, self).finish_shutdown(*args, **kwargs)

        # Add the input file to the configuration
        config = self.rpz_options.config_file()

        with config.rewrite(encoding='utf-8') as (read, write):
            for line in read:
                write.write(line)
                if line == 'inputs_outputs:\n':
                    write.write('  - name: jupyter_connection_file'
                                '  # Needed for reprozip-jupyter operations\n'
                                '    read_by_runs: [0]\n'
                                '    path: %s\n' % self.connection_file)


KernelManagerABC.register(RPZKernelManager)


class RPZExecutePreprocessor(ExecutePreprocessor):
    def __init__(self, options):
        self.rpz_options = options
        super(RPZExecutePreprocessor, self).__init__()

    def preprocess(self, nb, resources):
        # no change {
        path = resources.get('metadata', {}).get('path', '')
        if path == '':
            path = None

        kernel_name = nb.metadata.get('kernelspec', {}).get('name', 'python')
        if self.kernel_name:
            kernel_name = self.kernel_name
        self.log.info("Executing notebook with kernel: %s" % kernel_name)
        # } no change

        logger.info("Starting kernel...")

        # copied from start_new_kernel(), but using our KernelManager class {
        km = RPZKernelManager(kernel_name=kernel_name)
        km.rpz_options = self.rpz_options
        km.start_kernel(extra_arguments=self.extra_arguments,
                        cwd=path)  # changed not to hide stderr
        kc = km.client()
        kc.start_channels()
        try:
            kc.wait_for_ready(timeout=60)
        except RuntimeError:
            kc.stop_channels()
            km.shutdown_kernel()
            raise
        # } start_new_kernel()

        self.km, self.kc = km, kc
        logger.info("Kernel started")

        # no change {
        self.kc.allow_stdin = False

        try:
            nb, resources = super(ExecutePreprocessor, self).preprocess(
                nb, resources)
        except CellExecutionError:
            sys.exit(3)
        finally:
            self.kc.stop_channels()
            self.km.shutdown_kernel(now=False)  # changed from now=False

        return nb, resources
        # } no change


def trace_notebook(filename, save_notebook=True, **kwargs):
    with open(filename) as fp:
        notebook = nbformat.read(fp, as_version=4)
    preprocessor = RPZExecutePreprocessor(RPZOptions(**kwargs))
    preprocessor.preprocess(
        notebook,
        {'metadata': {'path': os.path.dirname(filename)}})
    if save_notebook:
        with open(filename, 'wt') as fp:
            nbformat.write(notebook, fp)
    return notebook


def cmd_trace_notebook(args):
    setup_logging('REPROZIP-JUPYTER-TRACE', args.verbosity)
    if not args.notebook:
        sys.stderr.write("missing notebook\n")
        sys.exit(2)
    return trace_notebook(args.notebook,
                          save_notebook=args.save_notebook,
                          verbosity=args.verbosity, dir=args.dir,
                          identify_packages=args.identify_packages,
                          find_inputs_outputs=args.find_inputs_outputs,
                          append=args.append)


def setup(parser):
    parser.add_argument('-d', '--dir',
                        help="where to store database and configuration file "
                             "(default: ./.reprozip-trace)")
    parser.add_argument(
        '--dont-save-notebook', action='store_false', default=True,
        dest='save_notebook',
        help="do not update the notebook file when executing")
    parser.add_argument(
        '--dont-identify-packages', action='store_false', default=True,
        dest='identify_packages',
        help="do not try identify which package each file comes from")
    parser.add_argument(
        '--find-inputs-outputs', action='store_true',
        default=False, dest='find_inputs_outputs',
        help="try to identify input and output files")
    parser.add_argument(
        '--dont-find-inputs-outputs', action='store_false',
        default=False, dest='find_inputs_outputs',
        help=argparse.SUPPRESS)
    parser.add_argument(
        '-c', '--continue', action='store_true', dest='append',
        help="add to the previous trace, don't replace it")
    parser.add_argument(
        '-w', '--overwrite', action='store_true', dest='overwrite',
        help="overwrite the previous trace, don't add to it")
    parser.add_argument('notebook', help="command-line to run under trace")
    parser.set_defaults(func=cmd_trace_notebook)
