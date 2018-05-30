# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Run notebooks in a packed environment.
"""

from __future__ import division, print_function, unicode_literals

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


logger = logging.getLogger('reprozip_jupyter')


@contextlib.contextmanager
def process_connection_file(original):
    with original.open('r') as fp:
        data = json.load(fp)

    data['ip'] = '0.0.0.0'  # Kernel should listen on all interfaces

    ports = [value for key, value in data.items() if key.endswith('_port')]

    fd, fixed_file = Path.tempfile(suffix='.json')
    with fixed_file.open('w') as fp:
        json.dump(data, fp)
    os.close(fd)

    yield fixed_file, ports

    fixed_file.remove()


class RPZKernelManager(IOLoopKernelManager):
    rpz_target = None
    rpz_verbosity = 1

    def _launch_kernel(self, kernel_cmd, **kw):
        # Need to parse kernel command-line to find the connection file
        logger.info("Kernel command-line: %s", ' '.join(kernel_cmd))
        connection_file = None
        for i, arg in enumerate(kernel_cmd):
            if arg == '-f':
                connection_file = Path(kernel_cmd[i + 1])
                break

        if connection_file is None:
            logger.critical("The notebook didn't pass a connection file to "
                            "the kernel")
            sys.exit(1)

        with process_connection_file(connection_file) as (fixed_file, ports):
            # Upload connection file to environment
            subprocess.check_call(
                ['reprounzip'] + (['-v'] * (self.rpz_verbosity - 1)) +
                ['docker', 'upload', self.rpz_target,
                 '%s:jupyter_connection_file' % fixed_file])

        docker_options = []
        for port in ports:
            docker_options.extend(['-p', '%d:%d' % (port, port)])

        return subprocess.Popen(
            ['reprounzip'] + (['-v'] * (self.rpz_verbosity - 1)) +
            ['docker', 'run'] +
            ['--docker-option=%s' % opt for opt in docker_options] +
            [self.rpz_target])


class RPZMappingKernelManager(MappingKernelManager):
    def __init__(self, **kwargs):
        kwargs['kernel_manager_class'] = \
            'reprozip_jupyter.run.RPZKernelManager'
        super(RPZMappingKernelManager, self).__init__(**kwargs)


def run_server(target, jupyter_args=None, verbosity=1):
    RPZKernelManager.rpz_target = target
    RPZKernelManager.rpz_verbosity = verbosity

    if not jupyter_args:
        jupyter_args = []

    logger.info("Starting Jupyter notebook")
    NotebookApp.launch_instance(argv=jupyter_args,
                                kernel_manager_class=RPZMappingKernelManager)


def cmd_run_server(args):
    setup_logging('REPROZIP-JUPYTER-SERVER', args.verbosity)
    if not args.target:
        sys.stderr.write("Missing experiment directory\n")
        sys.exit(2)

    run_server(args.target, args.jupyter_args, verbosity=args.verbosity)


def setup(parser):
    parser.add_argument('target', help="Experiment directory")
    parser.add_argument('jupyter_args', nargs=argparse.REMAINDER,
                        help="Arguments to pass to the notebook server")
    parser.set_defaults(func=cmd_run_server)
