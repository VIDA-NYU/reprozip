import unittest

from reprounzip.unpackers.common import unique_names, make_unique_name


class TestCommon(unittest.TestCase):
    def test_unique_names(self):
        """Tests the unique_names generator."""
        names = [next(unique_names) for i in range(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes))
        self.assertEqual(len(set(names)), len(names))

    def test_make_unique_name(self):
        """Tests the make_unique_name() function."""
        names = [make_unique_name(b'/some/prefix_') for i in range(3)]
        for n in names:
            self.assertTrue(n and isinstance(n, bytes) and
                            n[:13] == b'/some/prefix_')
        self.assertEqual(len(set(names)), len(names))
