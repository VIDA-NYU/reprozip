"""Trace a notebook to generate accompanying RPZ pack.
"""

from __future__ import division, print_function, unicode_literals

import argparse
from jupyter_client.launcher import launch_kernel
from jupyter_client.manager import KernelManager
from jupyter_client.managerabc import KernelManagerABC
import logging
from nbconvert.preprocessors import ExecutePreprocessor
import nbformat
import os
import sys

from reprozip.common import setup_logging


__version__ = '0.1'


class RPZKernelManager(KernelManager):
    def _launch_kernel(self, kernel_cmd, **kw):
        cmd = ['reprozip']
        cmd.extend(['-v'] * (self.rpz_args.verbosity - 1))
        cmd.append('trace')
        if self.rpz_args.dir:
            cmd.extend(['--dir', self.rpz_args.dir])
        if not self.rpz_args.identify_packages:
            cmd.append('--dont-identify-packages')
        if not self.rpz_args.find_inputs_outputs:
            cmd.append('--dont-find-inputs-outputs')
        if self.rpz_args.append:
            cmd.append('--continue')
        else:
            cmd.append('--overwrite')
        cmd.extend(kernel_cmd)

        logging.info("Executing: %r", cmd)
        return launch_kernel(cmd, **kw)

    def finish_shutdown(self, *args, **kwargs):
        kwargs['waittime'] = 600
        return super(RPZKernelManager, self).finish_shutdown(*args, **kwargs)


KernelManagerABC.register(RPZKernelManager)


class RPZExecutePreprocessor(ExecutePreprocessor):
    def __init__(self, args):
        self.rpz_args = args
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

        logging.info("Starting kernel...")

        # copied from start_new_kernel(), but using our KernelManager class {
        km = RPZKernelManager(kernel_name=kernel_name)
        km.rpz_args = self.rpz_args
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
        logging.info("Kernel started")

        # no change {
        self.kc.allow_stdin = False

        try:
            nb, resources = super(ExecutePreprocessor, self).preprocess(
                nb, resources)
        finally:
            self.kc.stop_channels()
            self.km.shutdown_kernel(now=False)  # changed from now=False

        return nb, resources
        # } no change

    def preprocess_cell(self, *args, **kwargs):
        logging.info("Preprocess cell")
        return super(RPZExecutePreprocessor, self).preprocess_cell(
            *args, **kwargs)


def trace_notebook(args):
    notebook_filename = args.notebook

    with open(notebook_filename) as fp:
        notebook = nbformat.read(fp, as_version=4)
    preprocessor = RPZExecutePreprocessor(args)
    preprocessor.preprocess(
        notebook,
        {'metadata': {'path': os.path.dirname(notebook_filename)}})
    with open(notebook_filename, 'wt') as fp:
        nbformat.write(notebook, fp)
    return notebook


def main():
    parser = argparse.ArgumentParser(
        description="This runs a Jupyter notebook under ReproZip trace to "
                    "generate the accompanying environment package",
        epilog="Please report issues to reprozip-users@vgc.poly.edu")
    parser.add_argument('--version', action='version',
                        version=__version__)
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        dest='verbosity',
                        help="augments verbosity level")
    parser.add_argument('-d', '--dir',
                        help="where to store database and configuration file "
                             "(default: ./.reprozip-trace)")
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

    args = parser.parse_args()
    setup_logging('REPROZIP-JUPYTER-TRACE', args.verbosity)
    if not args.notebook:
        parser.error("missing notebook")
        sys.exit(1)
    trace_notebook(args)
    sys.exit(0)


if __name__ == '__main__':
    main()
