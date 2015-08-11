# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions dealing with X servers.
"""

from __future__ import division, print_function, unicode_literals

import contextlib
import logging
import os
from rpaths import Path, PosixPath
import select
import socket
import struct
import threading

from reprounzip.utils import irange, iteritems


# #include <X11/Xauth.h>
#
# typedef struct xauth {
#        unsigned short  family;
#        unsigned short  address_length;
#        char    *address;
#        unsigned short  number_length;
#        char    *number;
#        unsigned short  name_length;
#        char    *name;
#        unsigned short  data_length;
#        char    *data;
# } Xauth;


_read_short = lambda fp: struct.unpack('>H', fp.read(2))[0]
_write_short = lambda i: struct.pack('>H', i)


def ascii(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('ascii')


class Xauth(object):
    """A record in an Xauthority file.
    """
    FAMILY_LOCAL = 256
    FAMILY_INTERNET = 0
    FAMILY_DECNET = 1
    FAMILY_CHAOS = 2
    FAMILY_INTERNET6 = 6
    FAMILY_SERVERINTERPRETED = 5

    def __init__(self, family, address, number, name, data):
        self.family = family
        self.address = address
        self.number = number
        self.name = name
        self.data = data

    @classmethod
    def from_file(cls, fp):
        family = _read_short(fp)
        address_length = _read_short(fp)
        address = fp.read(address_length)
        number_length = _read_short(fp)
        number = int(fp.read(number_length))
        name_length = _read_short(fp)
        name = fp.read(name_length)
        data_length = _read_short(fp)
        data = fp.read(data_length)

        return cls(family, address, number, name, data)

    def as_bytes(self):
        number = ('%d' % self.number).encode('ascii')
        return (_write_short(self.family) +
                _write_short(len(self.address)) +
                ascii(self.address) +
                _write_short(len(number)) +
                number +
                _write_short(len(self.name)) +
                ascii(self.name) +
                _write_short(len(self.data)) +
                ascii(self.data))


class X11Handler(object):
    """X11 handler.

    This selects a way to connect to the local X server and an authentication
    mechanism. If provides `fix_env()` to set the X environment variable for
    the experiment, `init_cmds` to setup X before running the experiment's main
    commands, and `port_forward` which describes the reverse port tunnels from
    the experiment to the local X server.
    """
    DISPLAY_NUMBER = 15

    SOCK2X = {socket.AF_INET: Xauth.FAMILY_INTERNET,
              socket.AF_INET6: Xauth.FAMILY_INTERNET6}
    X2SOCK = dict((v, k) for k, v in iteritems(SOCK2X))

    def __init__(self, enabled, target, display=None):
        self.enabled = enabled
        if not self.enabled:
            return

        self.target = target

        self.xauth = PosixPath('/.reprounzip_xauthority')
        self.display = display if display is not None else self.DISPLAY_NUMBER
        logging.debug("X11 support enabled; will create Xauthority file %s "
                      "for experiment. Display number is %d", self.xauth,
                      self.display)

        # List of addresses that match the $DISPLAY variable
        possible, local_display = self._locate_display()
        tcp_portnum = ((6000 + local_display) if local_display is not None
                       else None)

        if ('XAUTHORITY' in os.environ and
                Path(os.environ['XAUTHORITY']).is_file()):
            xauthority = Path(os.environ['XAUTHORITY'])
        # Note: I'm assuming here that Xauthority has no XDG support
        else:
            xauthority = Path('~').expand_user() / '.Xauthority'

        # Read Xauthority file
        xauth_entries = {}
        if xauthority.is_file():
            with xauthority.open('rb') as fp:
                fp.seek(0, os.SEEK_END)
                size = fp.tell()
                fp.seek(0, os.SEEK_SET)
                while fp.tell() < size:
                    entry = Xauth.from_file(fp)
                    if (entry.name == 'MIT-MAGIC-COOKIE-1' and
                            entry.number == local_display):
                        if entry.family == Xauth.FAMILY_LOCAL:
                            xauth_entries[(entry.family, None)] = entry
                        elif (entry.family == Xauth.FAMILY_INTERNET or
                                entry.family == Xauth.FAMILY_INTERNET6):
                            xauth_entries[(entry.family,
                                           entry.address)] = entry
        # FIXME: this completely ignores addresses

        logging.debug("Possible X endpoints: %s", (possible,))

        # Select socket and authentication cookie
        self.xauth_record = None
        self.connection_info = None
        for family, address in possible:
            # Checks that we have a cookie
            entry = family, (None if family is Xauth.FAMILY_LOCAL else address)
            if entry not in xauth_entries:
                continue
            if family == Xauth.FAMILY_LOCAL and hasattr(socket, 'AF_UNIX'):
                # Checks that the socket exists
                if not Path(address).exists():
                    continue
                self.connection_info = (socket.AF_UNIX, socket.SOCK_STREAM,
                                        address)
                self.xauth_record = xauth_entries[(family, None)]
                logging.debug("Will connect to local X display via UNIX "
                              "socket %s", address)
                break
            else:
                # Checks that we have a cookie
                family = self.X2SOCK[family]
                self.connection_info = (family, socket.SOCK_STREAM,
                                        (address, tcp_portnum))
                self.xauth_record = xauth_entries[(family, address)]
                logging.debug("Will connect to X display %s:%d via %s/TCP",
                              address, tcp_portnum,
                              "IPv6" if family == socket.AF_INET6 else "IPv4")
                break

        # Didn't find an Xauthority record -- assume no authentication is
        # needed, but still set self.connection_info
        if self.connection_info is None:
            for family, address in possible:
                # Only try UNIX sockets, we'll use 127.0.0.1 otherwise
                if family == Xauth.FAMILY_LOCAL:
                    if not hasattr(socket, 'AF_UNIX'):
                        continue
                    self.connection_info = (socket.AF_UNIX, socket.SOCK_STREAM,
                                            address)
                    logging.debug("Will connect to X display via UNIX socket "
                                  "%s, no authentication", address)
                    break
            else:
                self.connection_info = (socket.AF_INET, socket.SOCK_STREAM,
                                        ('127.0.0.1', tcp_portnum))
                logging.debug("Will connect to X display 127.0.0.1:%d via "
                              "IPv4/TCP, no authentication",
                              tcp_portnum)

        if self.connection_info is None:
            raise RuntimeError("Couldn't determine how to connect to local X "
                               "server, DISPLAY is %s" % (
                                   repr(os.environ['DISPLAY'])
                                   if 'DISPLAY' is os.environ
                                   else 'not set'))

    @classmethod
    def _locate_display(cls):
        """Reads $DISPLAY and figures out possible sockets.
        """
        # We default to ":0", Xming for instance doesn't set $DISPLAY
        display = os.environ.get('DISPLAY', ':0')

        # It might be the full path to a UNIX socket
        if display.startswith('/'):
            return [(Xauth.FAMILY_LOCAL, display)], None

        local_addr, local_display = display.rsplit(':', 1)
        local_display = int(local_display.split('.', 1)[0])

        # Let's order the socket families: IPv4 first, then v6, then others
        def sort_families(gai, order={socket.AF_INET: 0, socket.AF_INET6: 1}):
            return sorted(gai, key=lambda x: order.get(x[0], 999999))

        # Network addresses of the local machine
        local_addresses = []
        for family, socktype, proto, canonname, sockaddr in \
                sort_families(socket.getaddrinfo(socket.gethostname(), 6000)):
            try:
                family = cls.SOCK2X[family]
            except KeyError:
                continue
            local_addresses.append((family, sockaddr[0]))

        logging.debug("Local addresses: %s", (local_addresses,))

        # Determine possible addresses for $DISPLAY
        if not local_addr:
            possible = [(Xauth.FAMILY_LOCAL,
                         '/tmp/.X11-unix/X%d' % local_display)]
            possible += local_addresses
        else:
            local_possible = False
            possible = []
            for family, socktype, proto, canonname, sockaddr in \
                    sort_families(socket.getaddrinfo(local_addr, 6000)):
                try:
                    family = cls.SOCK2X[family]
                except KeyError:
                    continue
                if (family, sockaddr[0]) in local_addresses:
                    local_possible = True
                possible.append((family, sockaddr[0]))
            if local_possible:
                possible = [(Xauth.FAMILY_LOCAL,
                             '/tmp/.X11-unix/X%d' % local_display)] + possible

        return possible, local_display

    @property
    def port_forward(self):
        """Builds the port forwarding info, for `run_interactive()`.

        Just requests port 6015 on the remote host to be forwarded to the X
        socket identified by `self.connection_info`.
        """
        if not self.enabled:
            return []

        @contextlib.contextmanager
        def connect(src_addr):
            logging.info("Got remote X connection from %s", (src_addr,))
            logging.debug("Connecting to X server: %s",
                          (self.connection_info,))
            sock = socket.socket(*self.connection_info[:2])
            sock.connect(self.connection_info[2])
            yield sock
            sock.close()
            logging.info("X connection from %s closed", (src_addr,))

        return [(6000 + self.display, connect)]

    def fix_env(self, env):
        """Sets ``$XAUTHORITY`` and ``$DISPLAY`` in the environment.
        """
        if not self.enabled:
            return env
        new_env = dict(env)
        new_env['XAUTHORITY'] = str(self.xauth)
        if self.target[0] == 'local':
            new_env['DISPLAY'] = '127.0.0.1:%d' % self.display
        elif self.target[0] == 'internet':
            new_env['DISPLAY'] = '%s:%d' % (self.target[1], self.display)
        return new_env

    @property
    def init_cmds(self):
        """Gets the commands to setup X on the server before the experiment.
        """
        if not self.enabled or self.xauth_record is None:
            return []

        if self.target[0] == 'local':
            xauth_record = Xauth(Xauth.FAMILY_LOCAL,
                                 self.target[1],
                                 self.display,
                                 self.xauth_record.name,
                                 self.xauth_record.data)
        elif self.target[0] == 'internet':
            xauth_record = Xauth(Xauth.FAMILY_INTERNET,
                                 socket.inet_aton(self.target[1]),
                                 self.display,
                                 self.xauth_record.name,
                                 self.xauth_record.data)
        else:
            raise RuntimeError("Invalid target display type")
        buf = xauth_record.as_bytes()
        xauth = ''.join(('\\x%02x' % ord(buf[i:i + 1]))
                        for i in irange(len(buf)))
        return ['echo -ne "%s" > %s' % (xauth, self.xauth)]


class BaseForwarder(object):
    """Accepts connections and forwards to the given connector object.

    The `connector` is a function which takes the address of remote process
    connecting on this ends, and gives out a socket object that is the second
    endpoint of the tunnel. The socket object must provide ``recv()``,
    ``sendall()`` and ``close()``.

    Abstract class, implementations will provide actual ways to accept
    connections.
    """
    def __init__(self, connector):
        self.connector = connector

    def _forward(self, client, src_addr):
        try:
            with self.connector(src_addr) as local_connection:
                local_fd = local_connection.fileno()
                client_fd = client.fileno()
                while True:
                    r, w, x = select.select([local_fd, client_fd], [], [])
                    if local_fd in r:
                        data = local_connection.recv(4096)
                        if not data:
                            break
                        client.sendall(data)
                    elif client_fd in r:
                        data = client.recv(4096)
                        if not data:
                            break
                        local_connection.sendall(data)
        finally:
            client.close()


class LocalForwarder(BaseForwarder):
    """Listens on a random port and forwards to the given connector object.

    The `connector` is a function which takes the address of remote process
    connecting on this ends, and gives out a socket object that is the second
    endpoint of the tunnel. The socket object must provide ``recv()``,
    ``sendall()`` and ``close()``.
    """
    def __init__(self, connector, local_port=None):
        BaseForwarder.__init__(self, connector)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('', local_port or 0))
        self.local_port = server.getsockname()[1]
        server.listen(5)

        t = threading.Thread(target=self._accept, args=(server,))
        t.setDaemon(True)
        t.start()

    def _accept(self, server):
        while True:
            client, src_addr = server.accept()
            t = threading.Thread(target=self._forward,
                                 args=(client, src_addr))
            t.setDaemon(True)
            t.start()
