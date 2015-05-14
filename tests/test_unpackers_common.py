# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import unittest

from reprounzip.unpackers.common import unique_names, make_unique_name
from reprounzip.utils import irange


class TestCommon(unittest.TestCase):
    def test_unique_names(self):
        """Tests the unique_names generator."""
        names = [next(unique_names) for i in irange(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes))
        self.assertEqual(len(set(names)), len(names))

    def test_make_unique_name(self):
        """Tests the make_unique_name() function."""
        names = [make_unique_name(b'/some/prefix_') for i in irange(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes) and
                            n[:13] == b'/some/prefix_')
        self.assertEqual(len(set(names)), len(names))
