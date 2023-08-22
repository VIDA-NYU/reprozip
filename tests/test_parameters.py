# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import unittest

from reprounzip import parameters
from reprounzip_docker import select_image
from reprounzip_vagrant import select_box


class TestSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Make sure parameters are loaded
        parameters.update_parameters()

        # Reset them to bundled parameters temporarily
        cls._old_parameters = parameters.parameters
        parameters.parameters = parameters._bundled_parameters

    @classmethod
    def tearDownClass(cls):
        parameters.parameters = cls._old_parameters

    def test_docker(self):
        def get(architecture, distribution, version):
            return select_image({'architecture': architecture,
                                 'distribution': (distribution, version)})

        self.assertEqual(get('i686', 'Ubuntu', '14.10'),
                         ('ubuntu', 'ubuntu:14.10'))
        self.assertEqual(get('x86_64', 'Ubuntu', '14.10'),
                         ('ubuntu', 'ubuntu:14.10'))
        self.assertEqual(get('x86_64', 'Ubuntu', '1.1'),
                         ('ubuntu', 'ubuntu:19.04'))
        self.assertRaises(SystemExit, get, 'armv7', 'Debian', '8.2')
        self.assertEqual(get('x86_64', 'Arch', '2015.06.01'),
                         ('debian', 'debian:stretch'))
        self.assertEqual(get('x86_64', 'Debian', '1'),
                         ('debian', 'debian:stretch'))
        self.assertEqual(get('x86_64', 'CentOS', '1'),
                         ('centos', 'centos:centos7'))

    def test_vagrant(self):
        def get(architecture, distribution, version, gui=False):
            return select_box([{'architecture': architecture,
                                'distribution': (distribution, version)}],
                              gui=gui)

        self.assertEqual(get('i686', 'Ubuntu', '14.04'),
                         ('ubuntu', 'ubuntu/trusty32'))
        self.assertEqual(get('x86_64', 'Ubuntu', '12.04'),
                         ('ubuntu', 'hashicorp/precise64'))
        self.assertEqual(get('i686', 'Ubuntu', '1.1'),
                         ('ubuntu', 'bento/ubuntu-17.04-i386'))
        self.assertRaises(SystemExit, get, 'armv7', 'Debian', '8.2')
        self.assertEqual(get('x86_64', 'Arch', '2015.06.01'),
                         ('debian', 'bento/debian-10'))
        self.assertEqual(get('x86_64', 'Debian', '1'),
                         ('debian', 'bento/debian-10'))
        self.assertEqual(get('x86_64', 'CentOS', '1'),
                         ('centos', 'bento/centos-8'))
        self.assertEqual(get('x86_64', 'Fedora', '22'),
                         ('fedora', 'remram/fedora-22-amd64'))
        self.assertEqual(get('x86_64', 'Fedora', '22', gui=True),
                         ('debian', 'remram/debian-8-amd64-x'))
        self.assertEqual(get('x86_64', 'Ubuntu', '14.04', gui=True),
                         ('ubuntu', 'remram/ubuntu-1604-amd64-x'))
