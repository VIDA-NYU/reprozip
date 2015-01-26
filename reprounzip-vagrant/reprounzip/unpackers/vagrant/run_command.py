# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""SSH command runner.

This contains `run_interactive()`, used to run a command via SSH.
"""

import logging
import os
import paramiko
from paramiko.client import MissingHostKeyPolicy
import subprocess
import sys

from reprounzip.common import record_usage
from reprounzip.unpackers.vagrant.interaction import interactive_shell
from reprounzip.utils import irange


class IgnoreMissingKey(MissingHostKeyPolicy):
    """Policy that just ignores missing SSH host keys.

    We are connecting to vagrant, checking the host doesn't make sense, and
    accepting keys permanently is a security risk.
    """
    def missing_host_key(self, client, hostname, key):
        pass


def find_ssh_executable(name='ssh'):
    exts = os.environ.get('PATHEXT', '').split(os.pathsep)
    dirs = list(os.environ.get('PATH', '').split(os.pathsep))
    par, join = os.path.dirname, os.path.join
    # executable might be bin/python or ReproUnzip\python
    # or ReproUnzip\Python27\python or ReproUnzip\Python27\Scripts\something
    loc = par(sys.executable)
    local_dirs = []
    for i in irange(3):
        local_dirs.extend([loc, join(loc, 'ssh')])
        loc = par(loc)
    for pathdir in local_dirs + dirs:
        for ext in exts:
            fullpath = os.path.join(pathdir, name + ext)
            if os.path.isfile(fullpath):
                return fullpath
    return None


def run_interactive(ssh_info, interactive, cmds, request_pty):
    if interactive:
        ssh_exe = find_ssh_executable()
    else:
        ssh_exe = None

    if interactive and ssh_exe:
        record_usage(vagrant_ssh='ssh')
        return subprocess.call(
                [ssh_exe,
                 '-t' if request_pty else '-T',  # Force allocation of PTY
                 '-o', 'StrictHostKeyChecking=no',  # Silently accept host keys
                 '-o', 'UserKnownHostsFile=/dev/null',  # Don't store host keys
                 '-i', ssh_info['key_filename'],
                 '-p', '%d' % ssh_info['port'],
                 '%s@%s' % (ssh_info['username'],
                            ssh_info['hostname']),
                 cmds])
    else:
        record_usage(vagrant_ssh='interactive' if interactive else 'simple')
        # Connects to the machine
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(IgnoreMissingKey())
        ssh.connect(**ssh_info)

        chan = ssh.get_transport().open_session()
        if request_pty:
            chan.get_pty()

        # Execute command
        logging.info("Connected via SSH, running command...")
        chan.exec_command(cmds)

        # Get output
        if interactive:
            interactive_shell(chan)
        else:
            chan.shutdown_write()
            while True:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
        retcode = chan.recv_exit_status()
        ssh.close()
        return retcode
