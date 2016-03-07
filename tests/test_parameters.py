# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import json
import unittest

from reprounzip import parameters
from reprounzip.unpackers.docker import select_image


class TestSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Make sure parameters are loaded
        parameters.update_parameters()

        # Reset them to bundled parameters temporarily
        cls._old_parameters = parameters.parameters
        parameters.parameters = json.loads(parameters.bundled_parameters)

    @classmethod
    def tearDownClass(cls):
        parameters.parameters = cls._old_parameters

    def test_docker(self):
        def get(architecture, distribution, version):
            return select_image([{'architecture': architecture,
                                  'distribution': (distribution, version)}])

        self.assertEqual(get('i686', 'Ubuntu', '14.10'),
                         ('ubuntu', 'ubuntu:14.10'))
        self.assertEqual(get('x86_64', 'Ubuntu', '14.10'),
                         ('ubuntu', 'ubuntu:14.10'))
        self.assertEqual(get('x86_64', 'Ubuntu', '1.1'),
                         ('ubuntu', 'ubuntu:15.10'))
        self.assertRaises(SystemExit, get, 'armv7', 'Debian', '8.2')
        self.assertEqual(get('x86_64', 'Fedora', '12'),
                         ('debian', 'debian:jessie'))
        self.assertEqual(get('x86_64', 'Debian', '1'),
                         ('debian', 'debian:jessie'))
