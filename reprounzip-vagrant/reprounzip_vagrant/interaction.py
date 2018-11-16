# This is paramiko/demos/interactive.py
# Part of the Paramiko project; https://github.com/paramiko/paramiko/
# Adapted by Remi Rampin, New York University for ReproZip, 2015

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.


from __future__ import division, print_function, unicode_literals

import socket

from reprounzip.utils import stdout, stdout_bytes, stderr_bytes, stdin_bytes

# windows does not have termios...
try:
    import termios
    import tty
    has_termios = True
except ImportError:
    has_termios = False


def interactive_shell(chan, raw=True):
    if has_termios:
        posix_shell(chan, raw)
    else:
        windows_shell(chan)


def posix_shell(chan, raw):
    # set signal somehow
    import select

    oldtty = termios.tcgetattr(stdin_bytes)
    try:
        if raw:
            tty.setraw(stdin_bytes.fileno())
            tty.setcbreak(stdin_bytes.fileno())
        chan.settimeout(0.0)

        while True:
            r, w, e = select.select([chan, stdin_bytes], [], [])
            if chan in r:
                try:
                    if chan.recv_stderr_ready():
                        x = chan.recv_stderr(1024)
                        if len(x) > 0:
                            stderr_bytes.write(x)
                            stderr_bytes.flush()
                    else:
                        x = chan.recv(1024)
                        if len(x) == 0:
                            break
                        stdout_bytes.write(x)
                        stdout_bytes.flush()
                except socket.timeout:
                    pass
            if stdin_bytes in r:
                x = stdin_bytes.read(1)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        if raw:
            termios.tcsetattr(stdin_bytes, termios.TCSADRAIN, oldtty)


# thanks to Mike Looijmans for this code
def windows_shell(chan):
    # set signal somehow
    import threading

    stdout.write("*** Emulating terminal on Windows; press F6 or Ctrl+Z then "
                 "enter to send EOF,\r\nor at the end of the execution.\r\n")
    stdout.flush()

    out_lock = threading.RLock()

    def write(recv, std):
        while True:
            data = recv(256)
            if not data:
                if std:
                    with out_lock:
                        stdout.write(
                            "\r\n*** EOF reached; (press F6 or ^Z then enter "
                            "to end)\r\n")
                        stdout.flush()
                break
            stream = [stderr_bytes, stdout_bytes][std]
            with out_lock:
                stream.write(data)
                stream.flush()

    threading.Thread(target=write, args=(chan.recv, True)).start()
    threading.Thread(target=write, args=(chan.recv_stderr, False,)).start()

    try:
        while True:
            d = stdin_bytes.read(1)
            if not d:
                chan.shutdown_write()
                break
            try:
                chan.send(d)
            except socket.error:
                break
    except EOFError:
        # user hit ^Z or F6
        pass
