# Copyright (C) 2014-2017 New York University
# Copyright (C) 2017 Dirk Beyer
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Containerexec plugin for reprounzip."""

# prepare for Python 3
from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import logging
import signal
from rpaths import Path
import sys

from benchexec import BenchExecException, containerexecutor
from reprounzip import signals
from reprounzip.common import load_config as load_config_file
from reprounzip.unpackers.common import target_must_exist, shell_escape, \
    get_runs, add_environment_options, fixup_environment, metadata_read, \
    metadata_write, metadata_initial_iofiles, metadata_update_run
from reprounzip.unpackers.default import chroot_create, download, \
    test_linux_same_arch, upload
from reprounzip.utils import stderr, rmtree_fixed

TYPE_ = 'containerexec'


def containerexec_create(args):
    """Unpacks the experiment in a specified folder so it can be run with
    containerexec.

    The files in the rpz-file (pack) are unpacked to the target location, and
    system files are also copied if they are not already available in the pack.
    Busybox will be also installed in case /bin/sh wasn't packed.
    """
    chroot_create(args)

    # Rewrite the meta-data for reprounzip with a specific type-name
    # of the containerexec unpacker
    target = Path(args.target[0])
    config = load_config_file(target / 'config.yml', True)
    metadata_write(target, metadata_initial_iofiles(config), TYPE_)


@target_must_exist
def containerexec_run(args):
    """Runs the experiment in a container environment that is partially isolated
    from the host.

    The process is isolated from other processes on the same system, in a similar
    way as for example Docker isolates applications (using operating-level system
    virtualization).
    For further informations, see also
    https://github.com/sosy-lab/benchexec/blob/master/doc/container.md
    """
    if args is None:
        args = sys.args

    logging.info('Received arguments: %s', args)

    target = Path(args.target[0])
    unpacked_info = metadata_read(target, TYPE_)
    cmdline = args.cmdline

    # Loads config
    config = load_config_file(target / 'config.yml', True)
    runs = config.runs

    selected_runs = get_runs(runs, args.run, cmdline)

    root_dir = target / b"root"
    root_dir = str(root_dir.resolve())

    if args.x11 and not any('DISPLAY' in s for s in args.pass_env):
        args.pass_env.append('DISPLAY')

    signals.pre_run(target=target)

    # Each run is executed in its own executor process.
    for run_number in selected_runs:
        run = runs[run_number]

        working_dir = shell_escape(run['workingdir'])
        env = fixup_environment(run['environ'], args)

        uid = run['uid']
        gid = run['gid']

        # FIXME : Use exec -a or something if binary != argv[0]
        if cmdline is None:
            argv = [run['binary']] + run['argv'][1:]
        else:
            argv = cmdline

        executor = containerexecutor.ContainerExecutor(uid=uid, gid=gid,
                                                       network_access=True)

        # ensure that process gets killed on interrupt/kill signal
        def signal_handler_kill(signum, frame):
            executor.stop()
        signal.signal(signal.SIGTERM, signal_handler_kill)
        signal.signal(signal.SIGINT,  signal_handler_kill)

        # actual run execution
        try:
            result = executor.execute_run(argv, workingDir=working_dir,
                                          rootDir=root_dir, environ=env)
        except (BenchExecException, OSError) as e:
            sys.exit("Cannot execute process: {0}.".format(e))

    stderr.write("\n*** Command finished, status: %d\n" % result.value or result.signal)
    signals.post_run(target=target, retcode=result.value)

    # Update input file status
    metadata_update_run(config, unpacked_info, selected_runs)
    metadata_write(target, unpacked_info, TYPE_)


@target_must_exist
def containerexec_destroy(args):
    """Destroys the directory.
    """
    target = Path(args.target[0])

    logging.info("Removing directory %s...", target)
    signals.pre_destroy(target=target)
    rmtree_fixed(target)
    signals.post_destroy(target=target)


def setup(parser, **kwargs):
    """Unpacks the files in a directory and runs the experiment in a container
    that is partially isolated from the host. ContainerExec is part of
    BenchExec: https://github.com/sosy-lab/benchexec/

    setup           creates the directory (needs the pack filename)
    upload          replaces input files in the directory
                    (without arguments, lists input files)
    run             runs the experiment in a container
    download        gets output files from the machine
                    (without arguments, lists output files)
    destroy         removes the unpacked directory

    For example:

        $ reprounzip containerexec setup mypackage.rpz path
        $ reprounzip containerexec upload path/ input:/home/user/input.txt
        $ reprounzip containerexec run path/
        $ reprounzip containerexec download path/ results:/home/user/results.txt
        $ reprounzip containerexec destroy path

    Upload specifications are either:
      :input_id             restores the original input file from the pack
      filename:input_id     replaces the input file with the specified local
                            file

    Download specifications are either:
      output_id:            print the output file to stdout
      output_id:filename    extracts the output file to the corresponding local
                            path
    """

    subparsers = parser.add_subparsers(title="actions",
                                       metavar='', help=argparse.SUPPRESS)

    def add_opt_general(opts):
        opts.add_argument('target', nargs=1, help="Experiment directory")

    # setup
    parser_setup = subparsers.add_parser('setup')
    parser_setup.add_argument('pack', nargs=1, help="Pack to extract")
    add_opt_general(parser_setup)
    parser_setup.set_defaults(func=containerexec_create, restore_owner=False)

    # upload
    parser_upload = subparsers.add_parser('upload')
    add_opt_general(parser_upload)
    parser_upload.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                               help="<path>:<input_file_name")
    parser_upload.set_defaults(func=upload, type=TYPE_,
                               restore_owner=False)

    # run
    parser_run = subparsers.add_parser('run')
    add_opt_general(parser_run)
    parser_run.add_argument('run', default=None, nargs=argparse.OPTIONAL)
    parser_run.add_argument('--cmdline', nargs=argparse.REMAINDER,
                            help="Command line to run")
    parser_run.add_argument('--enable-x11', action='store_true', default=False,
                            dest='x11',
                            help="Enable X11 support (needs an X server on "
                                 "the host)")
    add_environment_options(parser_run)
    parser_run.set_defaults(func=containerexec_run)

    # download
    parser_download = subparsers.add_parser('download')
    add_opt_general(parser_download)
    parser_download.add_argument('file', nargs=argparse.ZERO_OR_MORE,
                                 help="<output_file_name>[:<path>]")
    parser_download.add_argument('--all', action='store_true',
                                 help="Download all output files to the "
                                      "current directory")
    parser_download.set_defaults(func=download, type=TYPE_)

    # destroy
    parser_destroy = subparsers.add_parser('destroy')
    add_opt_general(parser_destroy)
    parser_destroy.set_defaults(func=containerexec_destroy)

    return {'test_compatibility': test_linux_same_arch}
