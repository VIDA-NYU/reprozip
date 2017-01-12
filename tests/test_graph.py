# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import print_function, unicode_literals

import json
import os
from rpaths import Path
import sys
import unittest

from reprounzip.common import FILE_READ, FILE_WRITE, FILE_WDIR, FILE_STAT
from reprounzip.unpackers import graph
from reprounzip.unpackers.common import UsageError

from tests.common import make_database


class TestGraph(unittest.TestCase):
    """Generates graphs from a fabricated trace database."""
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if sys.version_info < (2, 7, 3):
            raise unittest.SkipTest("Python version not supported by reprozip")

        cls._trace = Path.tempdir(prefix='rpz_testdb_')
        conn = make_database([
            ('proc', 0, None, False),
            ('open', 0, "/some/dir", True, FILE_WDIR),
            ('exec', 0, "/bin/sh", "/some/dir", "sh\0script_1\0"),
            ('open', 0, "/usr/share/1_one.pyc", False, FILE_READ),
            ('open', 0, "/some/dir/one", False, FILE_WRITE),
            ('exec', 0, "/usr/bin/python", "/some/dir", "python\0drive.py\0"),
            ('open', 0, "/some/dir/drive.py", False, FILE_READ),
            ('open', 0, "/some/dir/one", False, FILE_READ),
            ('open', 0, "/etc/2_two.cfg", False, FILE_READ),
            ('proc', 1, 0, False),
            ('open', 1, "/some/dir", True, FILE_WDIR),
            ('exec', 1, "/some/dir/experiment", "/some/dir", "experiment\0"),
            ('open', 1, "/some/dir/one", False, FILE_STAT),
            ('open', 1, "/usr/lib/2_one.so", False, FILE_READ),
            ('open', 1, "/some/dir/two", False, FILE_WRITE),
            ('exec', 0, "/usr/bin/wc", "/some/dir", "wc\0out.txt\0"),
            ('open', 0, "/some/dir/two", False, FILE_READ),

            ('proc', 2, None, False),
            ('open', 2, "/some/dir", True, FILE_WDIR),
            ('exec', 2, "/bin/sh", "/some/dir", "sh\0script_2\0"),
            ('proc', 3, 2, True),
            ('open', 3, "/some/dir", True, FILE_WDIR),
            ('exec', 3, "/usr/bin/python", "/some/dir", "python\0-\0"),
            ('open', 3, "/some/dir/one", False, FILE_READ),
            ('open', 3, "/some/dir/thing", False, FILE_WRITE),
            ('exec', 2, "/some/dir/report", "/some/dir", "./report\0-v\0"),
            ('open', 2, "/some/dir/thing", False, FILE_READ),
            ('open', 2, "/some/dir/result", False, FILE_WRITE),
        ], cls._trace / 'trace.sqlite3')
        conn.close()
        with (cls._trace / 'config.yml').open('w', encoding='utf-8') as fp:
            fp.write("""\
version: "0.7"
runs:
- id: first run
  architecture: x86_64
  argv: [sh, "script_1"]
  binary: /some/dir/one
  distribution: [debian, '8.0']
  environ: {USER: remram}
  exitcode: 0
  uid: 1000
  gid: 1000
  hostname: test
  workingdir: /user/dir
- architecture: x86_64
  argv: ["sh", "script_2"]
  binary: /some/dir/one
  distribution: [debian, '8.0']
  environ: {USER: remram}
  exitcode: 0
  uid: 1000
  gid: 1000
  hostname: test
  workingdir: /user/dir

inputs_outputs:
- name: important
  path: "/some/dir/one"
  written_by_runs: [0]
  read_by_runs: [1]

packages:
- name: pkg1
  version: "1.0"
  size: 10000
  packfiles: true
  files:
  - "/usr/share/1_one.py"
  - "/usr/share/1_two.py"
  - "/usr/bin/wc"
- name: pkg2
  version: "1.0"
  size: 10000
  packfiles: true
  files:
  - "/usr/lib/2_one.so"
  - "/etc/2_two.cfg"
- name: python
  version: "2.7"
  size: 5000000
  packfiles: true
  files:
  - "/usr/bin/python"
- name: unused
  version: "0.1"
  size: 100
  packfiles: true
  files:
  - "/an/unused/file"

other_files:
- "/bin/sh"
- "/usr/share/1_one.pyc"
- "/some/dir/drive.py"
- "/some/dir/experiment"
- "/some/dir/report"
""")

    @classmethod
    def tearDownClass(cls):
        cls._trace.rmtree()

    def do_dot_test(self, expected, **kwargs):
        graph.Process._id_gen = 0
        fd, target = Path.tempfile(prefix='rpz_testgraph_', suffix='.dot')
        os.close(fd)
        try:
            graph.generate(target,
                           self._trace / 'config.yml',
                           self._trace / 'trace.sqlite3',
                           **kwargs)
            if expected is False:
                self.fail("DOT generation didn't fail as expected")
            with target.open('r') as fp:
                self.assertEqual(expected, fp.read())
        except UsageError:
            if expected is not False:
                raise
        finally:
            target.remove()

    def do_json_test(self, expected, **kwargs):
        graph.Process._id_gen = 0
        fd, target = Path.tempfile(prefix='rpz_testgraph_', suffix='.json')
        os.close(fd)
        try:
            graph.generate(target,
                           self._trace / 'config.yml',
                           self._trace / 'trace.sqlite3',
                           graph_format='json', **kwargs)
            if expected is False:
                self.fail("JSON generation didn't fail as expected")
            with target.open('r', encoding='utf-8') as fp:
                obj = json.load(fp)
            self.assertEqual(expected, obj)
        except SystemExit:
            if expected is not False:
                raise
        finally:
            target.remove()

    def do_tests(self, expected_dot, expected_json, **kwargs):
        self.do_dot_test(expected_dot, **kwargs)
        self.do_json_test(expected_json, **kwargs)

    def test_simple(self):
        self.do_tests(
            """\
digraph G {
    /* programs */
    node [shape=box fontcolor=white fillcolor=black style=filled];
    subgraph cluster_run0 {
        label="first run";
        prog0 [label="/bin/sh (0)"];
        prog1 [label="/usr/bin/python (0)"];
        prog0 -> prog1 [label="exec"];
        prog2 [label="/some/dir/experiment (1)"];
        prog1 -> prog2 [label="fork+exec"];
        prog3 [label="/usr/bin/wc (0)"];
        prog1 -> prog3 [label="exec"];
    }
    subgraph cluster_run1 {
        label="run1";
        prog4 [label="/bin/sh (2)"];
        prog5 [label="/usr/bin/python (3)",fillcolor="#666666"];
        prog4 -> prog5 [label="fork+exec"];
        prog6 [label="/some/dir/report (2)"];
        prog4 -> prog6 [label="exec"];
    }

    node [shape=ellipse fontcolor="#131C39" fillcolor="#C9D2ED"];

    /* system packages */
    subgraph cluster_pkg0 {
        label="pkg1 1.0";
        "/usr/bin/wc";
    }
    subgraph cluster_pkg1 {
        label="pkg2 1.0";
        "/etc/2_two.cfg";
        "/usr/lib/2_one.so";
    }
    subgraph cluster_pkg2 {
        label="python 2.7";
        "/usr/bin/python";
    }

    /* other files */
    "/bin/sh";
    "/some/dir/drive.py";
    "/some/dir/experiment";
    "/some/dir/one" [fillcolor="#A3B4E0", label="important\\n/some/dir/one"];
    "/some/dir/report";
    "/some/dir/result";
    "/some/dir/thing";
    "/some/dir/two";
    "/usr/share/1_one.pyc";

    "/bin/sh" -> prog0 [style=bold, label="sh script_1"];
    "/usr/share/1_one.pyc" -> prog0 [color="#8888CC"];
    prog0 -> "/some/dir/one" [color="#000088"];
    "/usr/bin/python" -> prog1 [style=bold, label="python drive.py"];
    "/some/dir/drive.py" -> prog1 [color="#8888CC"];
    "/some/dir/one" -> prog1 [color="#8888CC"];
    "/etc/2_two.cfg" -> prog1 [color="#8888CC"];
    "/some/dir/experiment" -> prog2 [style=bold, label="experiment"];
    "/usr/lib/2_one.so" -> prog2 [color="#8888CC"];
    prog2 -> "/some/dir/two" [color="#000088"];
    "/usr/bin/wc" -> prog3 [style=bold, label="wc out.txt"];
    "/some/dir/two" -> prog3 [color="#8888CC"];
    "/bin/sh" -> prog4 [style=bold, label="sh script_2"];
    "/usr/bin/python" -> prog5 [style=bold, label="python -"];
    "/some/dir/one" -> prog5 [color="#8888CC"];
    prog5 -> "/some/dir/thing" [color="#000088"];
    "/some/dir/report" -> prog6 [style=bold, label="./report -v"];
    "/some/dir/thing" -> prog6 [color="#8888CC"];
    prog6 -> "/some/dir/result" [color="#000088"];
}
""",
            {'packages': [{'name': 'pkg1', 'version': '1.0',
                           'files': ['/usr/bin/wc']},
                          {'name': 'pkg2', 'version': '1.0',
                           'files': ['/etc/2_two.cfg',
                                     '/usr/lib/2_one.so']},
                          {'name': 'python', 'version': '2.7',
                           'files': ['/usr/bin/python']}],
             'other_files': ['/bin/sh',
                             '/some/dir/drive.py',
                             '/some/dir/experiment',
                             '/some/dir/one',
                             '/some/dir/report',
                             '/some/dir/result',
                             '/some/dir/thing',
                             '/some/dir/two',
                             '/usr/share/1_one.pyc'],
             'runs': [[{'name': '0',
                        'long_name': 'sh (0)',
                        'description': '/bin/sh\n0',
                        'parent': None,
                        'reads': ['/bin/sh', '/usr/share/1_one.pyc'],
                        'writes': ['/some/dir/one']},
                       {'name': '0',
                        'long_name': 'python (0)',
                        'description': '/usr/bin/python\n0',
                        'parent': [0, 'exec'],
                        'reads': ['/usr/bin/python',
                                  '/some/dir/drive.py',
                                  '/some/dir/one',
                                  '/etc/2_two.cfg'],
                        'writes': []},
                       {'name': '1',
                        'long_name': 'experiment (1)',
                        'description': '/some/dir/experiment\n1',
                        'parent': [1, 'fork+exec'],
                        'reads': ['/some/dir/experiment',
                                  '/usr/lib/2_one.so'],
                        'writes': ['/some/dir/two']},
                       {'name': '0',
                        'long_name': 'wc (0)',
                        'description': '/usr/bin/wc\n0',
                        'parent': [1, 'exec'],
                        'reads': ['/usr/bin/wc', '/some/dir/two'],
                        'writes': []}],

                      [{'name': '2',
                        'long_name': 'sh (2)',
                        'description': '/bin/sh\n2',
                        'parent': None,
                        'reads': ['/bin/sh'],
                        'writes': []},
                       {'name': '3',
                        'long_name': 'python (3)',
                        'description': '/usr/bin/python\n3',
                        'parent': [0, 'fork+exec'],
                        'reads': ['/usr/bin/python', '/some/dir/one'],
                        'writes': ['/some/dir/thing']},
                       {'name': '2',
                        'long_name': 'report (2)',
                        'description': '/some/dir/report\n2',
                        'parent': [0, 'exec'],
                        'reads': ['/some/dir/report', '/some/dir/thing'],
                        'writes': ['/some/dir/result']}]]})

    def test_collapsed_packages(self):
        self.do_tests(
            """\
digraph G {
    /* programs */
    node [shape=box fontcolor=white fillcolor=black style=filled];
    subgraph cluster_run0 {
        label="first run";
        prog0 [label="/bin/sh (0)"];
        prog1 [label="/usr/bin/python (0)"];
        prog0 -> prog1 [label="exec"];
        prog2 [label="/some/dir/experiment (1)"];
        prog1 -> prog2 [label="fork+exec"];
        prog3 [label="/usr/bin/wc (0)"];
        prog1 -> prog3 [label="exec"];
    }
    subgraph cluster_run1 {
        label="run1";
        prog4 [label="/bin/sh (2)"];
        prog5 [label="/usr/bin/python (3)",fillcolor="#666666"];
        prog4 -> prog5 [label="fork+exec"];
        prog6 [label="/some/dir/report (2)"];
        prog4 -> prog6 [label="exec"];
    }

    node [shape=ellipse fontcolor="#131C39" fillcolor="#C9D2ED"];

    /* system packages */
    "pkg pkg1" [shape=box,label="pkg1 1.0"];
    "pkg pkg2" [shape=box,label="pkg2 1.0"];
    "pkg python" [shape=box,label="python 2.7"];

    /* other files */
    "/bin/sh";
    "/some/dir/drive.py";
    "/some/dir/experiment";
    "/some/dir/one" [fillcolor="#A3B4E0", label="important\\n/some/dir/one"];
    "/some/dir/report";
    "/some/dir/result";
    "/some/dir/thing";
    "/some/dir/two";

    "/bin/sh" -> prog0 [style=bold, label="sh script_1"];
    "pkg pkg1" -> prog0 [color="#8888CC"];
    prog0 -> "/some/dir/one" [color="#000088"];
    "pkg python" -> prog1 [style=bold, label="python drive.py"];
    "/some/dir/drive.py" -> prog1 [color="#8888CC"];
    "/some/dir/one" -> prog1 [color="#8888CC"];
    "pkg pkg2" -> prog1 [color="#8888CC"];
    "/some/dir/experiment" -> prog2 [style=bold, label="experiment"];
    "pkg pkg2" -> prog2 [color="#8888CC"];
    prog2 -> "/some/dir/two" [color="#000088"];
    "pkg pkg1" -> prog3 [style=bold, label="wc out.txt"];
    "/some/dir/two" -> prog3 [color="#8888CC"];
    "/bin/sh" -> prog4 [style=bold, label="sh script_2"];
    "pkg python" -> prog5 [style=bold, label="python -"];
    "/some/dir/one" -> prog5 [color="#8888CC"];
    prog5 -> "/some/dir/thing" [color="#000088"];
    "/some/dir/report" -> prog6 [style=bold, label="./report -v"];
    "/some/dir/thing" -> prog6 [color="#8888CC"];
    prog6 -> "/some/dir/result" [color="#000088"];
}
""",
            False,
            level_pkgs='package',
            regex_replaces=[('.pyc$', '.py')])
