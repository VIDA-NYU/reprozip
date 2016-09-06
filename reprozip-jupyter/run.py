"""Run notebooks in a packed environment.
"""

from __future__ import division, print_function, unicode_literals

import argparse
from jupyter_client.ioloop import IOLoopKernelManager
import logging
from notebook.notebookapp import NotebookApp
from notebook.services.kernels.kernelmanager import MappingKernelManager
import sys

from reprounzip.common import setup_logging
from reprounzip.unpackers.docker import docker_run


__version__ = '0.1'


class RPZKernelManager(IOLoopKernelManager):
    def _launch_kernel(self, kernel_cmd, **kw):
        cmd = TODO
        
        return launch_kernel(cmd, **kw)


class RPZMappingKernelManager(MappingKernelManager):
    def __init__(self, **kwargs):
        kwargs['kernel_manager_class'] = RPZKernelManager
        super(RPZMappingKernelManager, self).__init__(**kwargs)


def run_server(args):
    target = args.target_directory

    docker_run(argparse.Namespace(
        target=[target],
        run=None,
        x11=False,
        detach=False,
        pass_env=None, set_env=None,
        cmdline=None,
        x11_display=None,
        docker_option=[]))

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
    parser.add_argument('target_directory', help="Experiment directory")
    parser.add_argument('jupyter_args', nargs=argparse.REMAINDER,
                        help="Arguments to pass to the notebook server")

    args = parser.parse_args()
    setup_logging('REPROZIP-JUPYTER-SERVER', args.verbosity)
    if not args.target_directory:
        parser.error("missing experiment directory")
        sys.exit(1)
    run_server(args)
    sys.exit(0)


if __name__ == '__main__':
    main()
