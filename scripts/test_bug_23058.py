from __future__ import unicode_literals

import argparse
import unittest


class Test23058(unittest.TestCase):
    def do_test_verbosity(self, parser, line, expected_verbosity):
        try:
            args = parser.parse_args(line.split())
        except SystemExit:
            self.fail("Parsing arguments failed")
        self.assertEqual(args.verbosity, expected_verbosity)

    def test_parents(self):
        options = argparse.ArgumentParser(add_help=False)
        options.add_argument('-v', '--verbose', action='count', default=1,
                             dest='verbosity')

        parser = argparse.ArgumentParser(parents=[options])

        subparsers = parser.add_subparsers()

        command = subparsers.add_parser('command', parents=[options])

        self.do_test_verbosity(parser, 'command', 1)
        self.do_test_verbosity(parser, 'command -v', 2)
        self.do_test_verbosity(parser, 'command -v -v', 3)
        self.do_test_verbosity(parser, '-v command', 2)  # FAILS
            # arguments passed to main parser are *silently ignored*
        self.do_test_verbosity(parser, '-v -v command', 3)
        self.do_test_verbosity(parser, '-v -v command -v -v', 5)

    def test_function(self):
        def add_options(prs):
            prs.add_argument('-v', '--verbose', action='count', default=1,
                             dest='verbosity')

        parser = argparse.ArgumentParser()
        add_options(parser)

        subparsers = parser.add_subparsers()

        command = subparsers.add_parser('command')
        add_options(command)

        self.do_test_verbosity(parser, 'command', 1)
        self.do_test_verbosity(parser, 'command -v', 2)
        self.do_test_verbosity(parser, 'command -v -v', 3)
        self.do_test_verbosity(parser, '-v command', 2)  # FAILS
            # arguments passed to main parser are *silently ignored*
        self.do_test_verbosity(parser, '-v -v command', 3)
        self.do_test_verbosity(parser, '-v -v command -v -v', 5)


if __name__ == '__main__':
    unittest.main()
