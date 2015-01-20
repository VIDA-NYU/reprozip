# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions dealing with X servers.
"""

from __future__ import unicode_literals

import struct


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
