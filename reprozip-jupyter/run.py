"""Run notebooks in a packed environment.
"""

from __future__ import division, print_function, unicode_literals

if __name__ == '__main__':  # noqa
    from run import main
    main()

import argparse
import contextlib
import json
from jupyter_client.ioloop import IOLoopKernelManager
import logging
from notebook.notebookapp import NotebookApp
from notebook.services.kernels.kernelmanager import MappingKernelManager
import os
from rpaths import Path
import subprocess
import sys

from reprounzip.common import setup_logging
from reprounzip.utils import iteritems


__version__ = '0.1'


@contextlib.contextmanager
def process_connection_file(original):
    with original.open('rb') as fp:
        data = json.load(fp)

    data['ip'] = '0.0.0.0'  # Kernel should listen on all interfaces

    ports = [value for key, value in iteritems(data) if key.endswith('_port')]

    fd, fixed_file = Path.tempfile(suffix='.json')
    with fixed_file.open('wb') as fp:
        json.dump(data, fp)
    os.close(fd)

    yield fixed_file, ports

    fixed_file.remove()


class RPZKernelManager(IOLoopKernelManager):
    rpz_args = None

    def _launch_kernel(self, kernel_cmd, **kw):
        target = self.rpz_args.target

        # Need to parse kernel command-line to find the connection file
        logging.info("Kernel command-line: %s", ' '.join(kernel_cmd))
        connection_file = None
        for i, arg in enumerate(kernel_cmd):
            if arg == '-f':
                connection_file = Path(kernel_cmd[i + 1])
                break

        if connection_file is None:
            logging.critical("The notebook didn't pass a connection file to "
                             "the kernel")
            sys.exit(1)

        with process_connection_file(connection_file) as (fixed_file, ports):
            # Upload connection file to environment
            subprocess.check_call(
                ['reprounzip'] + (['-v'] * (self.rpz_args.verbosity - 1)) +
                 ['docker', 'upload', target,
                  '%s:jupyter_connection_file' % fixed_file])

        docker_options = []
        for port in ports:
            docker_options.extend(['-p', '%d:%d' % (port, port)])

        return subprocess.Popen(
            ['reprounzip'] + (['-v'] * (self.rpz_args.verbosity - 1)) +
            ['docker', 'run'] +
            ['--docker-option=%s' % opt for opt in docker_options] +
            [target])


class RPZMappingKernelManager(MappingKernelManager):
    def __init__(self, **kwargs):
        kwargs['kernel_manager_class'] = 'run.RPZKernelManager'
        super(RPZMappingKernelManager, self).__init__(**kwargs)


def run_server(args):
    RPZKernelManager.rpz_args = args

    logging.info("Starting Jupyter notebook")
    NotebookApp.launch_instance(argv=args.jupyter_args,
                                kernel_manager_class=RPZMappingKernelManager)


def main():
    parser = argparse.ArgumentParser(
        description="This runs a Jupyter notebook server that will spawn "
                    "notebooks in Docker containers started from the given "
                    "ReproZip package",
        epilog="Please report issues to reprozip-users@vgc.poly.edu")
    parser.add_argument('--version', action='version',
                        version=__version__)
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        dest='verbosity',
                        help="augments verbosity level")
    parser.add_argument('target', help="Experiment directory")
    parser.add_argument('jupyter_args', nargs=argparse.REMAINDER,
                        help="Arguments to pass to the notebook server")

    args = parser.parse_args()
    setup_logging('REPROZIP-JUPYTER-SERVER', args.verbosity)
    if not args.target:
        parser.error("missing experiment directory")
        sys.exit(1)
    run_server(args)
    sys.exit(0)
