# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""SSH command runner.

This contains `run_interactive()`, used to run a command via SSH.
"""

from __future__ import division, print_function, unicode_literals

import logging
import os
import paramiko
from paramiko.client import MissingHostKeyPolicy
import sys
import threading

from reprounzip.common import record_usage
from reprounzip.unpackers.common import interruptible_call
from reprounzip.unpackers.common.x11 import BaseForwarder, LocalForwarder
from reprounzip.unpackers.vagrant.interaction import interactive_shell
from reprounzip.utils import irange, stdout_bytes


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


class SSHForwarder(BaseForwarder):
    """Gets a remote port from paramiko and forwards to the given connector.

    The `connector` is a function which takes the address of remote process
    connecting on the port on the SSH server, and gives out a socket object
    that is the second endpoint of the tunnel. The socket object must provide
    ``recv()``, ``sendall()`` and ``close()``.
    """
    def __init__(self, ssh_transport, remote_port, connector):
        BaseForwarder.__init__(self, connector)
        ssh_transport.request_port_forward('', remote_port,
                                           self._new_connection)

    class _ChannelWrapper(object):
        def __init__(self, channel):
            self.channel = channel

        def sendall(self, data):
            return self.channel.send(data)

        def recv(self, data):
            return self.channel.recv(data)

        def close(self):
            self.channel.close()

    def _new_connection(self, channel, src_addr, dest_addr):
        # Wraps the channel as a socket-like object that _forward() can use
        socklike = self._ChannelWrapper(channel)
        t = threading.Thread(target=self._forward,
                             args=(socklike, src_addr))
        t.setDaemon(True)
        t.start()


def run_interactive(ssh_info, interactive, cmd, request_pty, forwarded_ports):
    """Runs a command on an SSH server.

    If `interactive` is True, we'll try to find an ``ssh`` executable, falling
    back to paramiko if it's not found. The terminal handling code is a bit
    wonky, so using ``ssh`` is definitely a good idea, especially on Windows.
    Non-interactive commands should run fine.

    :param ssh_info: dict with `hostname`, `port`, `username`, `key_filename`,
    passed directly to paramiko
    :type ssh_info: dict
    :param interactive: whether to connect local input to the remote process
    :type interactive: bool
    :param cmd: command-line to run on the server
    :type cmd: basestring
    :param request_pty: whether to request a PTY from the SSH server
    :type request_pty: bool
    :param forwarded_ports: ports to forward back to us; iterable of pairs
    ``(port_number, connector)`` where `port_number` is the remote port number
    and `connector` is the connector object used to build the connected socket
    to forward to on this side
    """
    if interactive:
        ssh_exe = find_ssh_executable()
    else:
        ssh_exe = None

    if interactive and ssh_exe:
        record_usage(vagrant_ssh='ssh')
        args = [ssh_exe,
                '-t' if request_pty else '-T',  # Force allocation of PTY
                '-o', 'StrictHostKeyChecking=no',  # Silently accept host keys
                '-o', 'UserKnownHostsFile=/dev/null',  # Don't store host keys
                '-i', ssh_info['key_filename'],
                '-p', '%d' % ssh_info['port']]
        for remote_port, connector in forwarded_ports:
            # Remote port will connect to a local port
            fwd = LocalForwarder(connector)
            args.append('-R%d:127.0.0.1:%d' % (remote_port, fwd.local_port))
        args.append('%s@%s' % (ssh_info['username'],
                               ssh_info['hostname']))
        args.append(cmd)
        return interruptible_call(args)

    else:
        record_usage(vagrant_ssh='interactive' if interactive else 'simple')
        # Connects to the machine
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(IgnoreMissingKey())
        ssh.connect(**ssh_info)

        # Starts forwarding
        forwarders = []
        for remote_port, connector in forwarded_ports:
            forwarders.append(
                SSHForwarder(ssh.get_transport(), remote_port, connector))

        chan = ssh.get_transport().open_session()
        if request_pty:
            chan.get_pty()

        # Execute command
        logging.info("Connected via SSH, running command...")
        chan.exec_command(cmd)

        # Get output
        if interactive:
            interactive_shell(chan)
        else:
            chan.shutdown_write()
            while True:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                stdout_bytes.write(data)
                stdout_bytes.flush()
        retcode = chan.recv_exit_status()
        ssh.close()
        return retcode
