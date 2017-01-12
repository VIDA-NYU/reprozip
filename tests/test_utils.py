# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import unittest

from reprounzip.utils import optional_return_type


class TestOptionalReturnType(unittest.TestCase):
    def test_namedtuple(self):
        T = optional_return_type(['a', 'b', 'c'], [])
        for o in [T(1, 2, 3), T(1, b=2, c=3), T(a=1, b=2, c=3)]:
            self.assertEqual(o, (1, 2, 3))
            self.assertEqual(o[0], 1)
            self.assertEqual(o[2], 3)
            self.assertRaises(IndexError, lambda: o[3])
            self.assertEqual(o.a, 1)
            self.assertEqual(o.c, 3)
        self.assertRaises(TypeError, lambda: T(1, 2))
        self.assertRaises(TypeError, lambda: T(a=1, b=2))
        self.assertRaises(TypeError, lambda: T(a=1, b=2))

    def test_with_opt(self):
        T = optional_return_type(['a', 'b'], ['c'])
        for o in [T(1, 2, 3), T(1, b=2, c=3), T(a=1, b=2, c=3)]:
            self.assertEqual(o, (1, 2))
            self.assertEqual(o[0], 1)
            self.assertEqual(o[1], 2)
            self.assertRaises(IndexError, lambda: o[2])
            self.assertEqual(o.a, 1)
            self.assertEqual(o.b, 2)
            self.assertEqual(o.c, 3)
        for o in [T(1, 2), T(1, b=2), T(a=1, b=2)]:
            self.assertEqual(o, (1, 2))
            self.assertEqual(o[0], 1)
            self.assertEqual(o[1], 2)
            self.assertRaises(IndexError, lambda: o[2])
            self.assertEqual(o.a, 1)
            self.assertEqual(o.b, 2)
            self.assertRaises(AttributeError, lambda: o.c)
        self.assertRaises(TypeError, lambda: T(1))
        self.assertRaises(TypeError, lambda: T(b=1, c=2))
        self.assertRaises(TypeError, lambda: T(c=1))
