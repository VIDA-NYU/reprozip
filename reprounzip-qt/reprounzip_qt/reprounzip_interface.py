# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import itertools
import os
import pickle
import platform
import subprocess
import sys
import time
import yaml

from reprounzip_qt.qt_terminal import run_in_builtin_terminal


safe_shell_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       "-+=/:.,%_")


def shell_escape(s):
    r"""Given bl"a, returns "bl\\"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if not s or any(c not in safe_shell_chars for c in s):
        return '"%s"' % (s.replace('\\', '\\\\')
                          .replace('"', '\\"')
                          .replace('$', '\\$'))
    else:
        return s


safe_win_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789"
                     "-+=/:.,_\\$")


def win_escape(s):
    r"""Given bl"a, returns "bl^"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if any(c not in safe_win_chars for c in s):
        return '"%s"' % (s.replace('^', '^^')
                          .replace('"', '^"')
                          .replace('%', '^%'))
    else:
        return s


if sys.platform.startswith('win'):
    native_escape = win_escape
else:
    native_escape = shell_escape


def check_directory(directory):
    if os.path.isdir(directory):
        filename = os.path.join(directory, '.reprounzip')
        if os.path.isfile(filename):
            with open(filename, 'rb') as fp:
                unpacked_info = pickle.load(fp)
            return unpacked_info['unpacker']
    return None


class FileStatus(object):
    def __init__(self, name, path, is_input, is_output):
        self.name = name
        self.path = path
        self.assigned = None
        self.is_input = is_input
        self.is_output = is_output


class FilesStatus(object):
    def __init__(self, directory):
        self.directory = directory
        with open(os.path.join(directory, 'config.yml')) as fp:
            config = yaml.safe_load(fp)

        self.files = [FileStatus(f['name'], f['path'],
                                 f.get('read_by_runs'),
                                 f.get('written_by_runs'))
                      for f in config.get('inputs_outputs') or []]
        self._refresh()

    def _refresh(self):
        with open(os.path.join(self.directory, '.reprounzip'), 'rb') as fp:
            unpacked_info = pickle.load(fp)
        assigned_input_files = unpacked_info.get('input_files', {})
        for f in self.files:
            f.assigned = assigned_input_files.get(f.name)

    def __getitem__(self, item):
        self._refresh()
        return self.files[item]

    def __iter__(self):
        self._refresh()
        return iter(self.files)


def find_command(cmd):
    if sys.platform.startswith('win'):
        for path in os.environ.get('PATH', '').split(os.pathsep):
            for ext in ('.bat', '.exe', '.cmd'):
                filename = os.path.join(path, cmd + ext)
                if os.path.exists(filename):
                    return filename
    else:
        for path in itertools.chain(
                os.environ.get('PATH', '').split(os.pathsep),
                ['/usr/local/bin', '/opt/reprounzip']):
            filename = os.path.join(path, cmd)
            if os.path.exists(filename):
                return filename
    return None


def run(directory, unpacker=None, runs=None,
        root=None, args=[]):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    run_in_system_terminal(
        [reprounzip, unpacker, 'run'] +
        args +
        [os.path.abspath(directory)] +
        ([','.join('%d' % r for r in runs)] if runs is not None else []),
        root=root)
    return True


def unpack(package, unpacker, directory, options=None):
    if options is None:
        options = {}

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    cmd = ([reprounzip, unpacker, 'setup'] +
           options.get('args', []) +
           [os.path.abspath(package), os.path.abspath(directory)])

    code = run_in_builtin_terminal_maybe(
        cmd, options.get('root', None),
        text="Unpacking experiment...",
        success_msg="Successfully setup experiment",
        fail_msg="Error setting up experiment")
    if code is None:
        return os.path.exists(directory)
    else:
        return code == 0


def destroy(directory, unpacker=None, root=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    code = run_in_builtin_terminal_maybe(
        [reprounzip, unpacker, 'destroy', os.path.abspath(directory)], root,
        text="Destroying experiment directory...",
        success_msg="Successfully destroyed experiment directory",
        fail_msg="Error destroying experiment")
    if code is None:
        return not os.path.exists(directory)
    else:
        return code == 0


def upload(directory, name, path, unpacker=None, root=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    if path is None:
        spec = ':%s' % name
    else:
        spec = '%s:%s' % (path, name)

    code = run_in_builtin_terminal_maybe(
        [reprounzip, unpacker, 'upload', os.path.abspath(directory), spec],
        root,
        text="Uploading file...",
        success_msg="Successfully replaced file",
        fail_msg="Error uploading file")
    if code is None:
        return True
    else:
        return code == 0


def download(directory, name, path, unpacker=None, root=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    spec = '%s:%s' % (name, path)

    code = run_in_builtin_terminal_maybe(
        [reprounzip, unpacker, 'download', os.path.abspath(directory), spec],
        root,
        text="Downloading file...",
        success_msg="Successfully downloaded file",
        fail_msg="Error downloading file")
    if code is None:
        return True
    else:
        return code == 0


def run_in_builtin_terminal_maybe(cmd, root, **kwargs):
    if root is None:
        code = run_in_builtin_terminal(cmd, **kwargs)
        return code
    else:
        run_in_system_terminal(cmd, root=root)
        return None


def run_in_system_terminal(cmd, wait=True, close_on_success=False, root=None):
    if root is None:
        pass
    elif root == 'sudo':
        cmd = ['sudo'] + cmd
    elif root == 'su':
        cmd = ['su', '-c', ' '.join(native_escape(a) for a in cmd)]
    else:
        assert False

    cmd = ' '.join(native_escape(c) for c in cmd)

    system = platform.system().lower()
    if system == 'darwin':
        # Dodge py2app issues
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONHOME', None)
        proc = subprocess.Popen(['/usr/bin/osascript', '-'],
                                stdin=subprocess.PIPE, env=env)
        run_script = """\
tell application "Terminal"
    activate
    set w to do script %s
%s
%s
end tell
"""
        wait_script = """\
    repeat
        delay 1
        if not busy of w then exit repeat
    end repeat
"""
        close_script = """\
    activate
    tell (first window whose tabs contain w)
        set selected tab to w
        tell application "System Events"
            tell process "Terminal"
                keystroke "w" using {command down}
            end tell
        end tell
    end tell
"""

        if not wait:
            wait_script = ''
        if close_on_success:
            cmd = cmd + ' && exit'
        else:
            cmd = cmd + '; exit'
            close_script = ''
        run_script = run_script % (shell_escape(cmd),
                                   wait_script,
                                   close_script)

        proc.communicate(run_script)
        proc.wait()
        if wait:
            time.sleep(0.5)
        return None
    elif system == 'windows':
        subprocess.check_call('start /wait cmd /c %s' %
                              win_escape(cmd + ' & pause'),
                              shell=True)
        return None
    elif system == 'linux':
        for term, arg_factory in [('konsole', lambda a: ['--nofork', '-e', a]),
                                  ('lxterminal', lambda a: ['--command=' + a]),
                                  ('rxvt', lambda a: ['-e', a]),
                                  ('xterm', lambda a: ['-e', a]),
                                  # gnome-terminal needs some kind of --nofork
                                  ('gnome-terminal', lambda a: ['-x', 'a'])]:
            if find_command(term) is not None:
                args = arg_factory(cmd)
                print([term] + args)
                subprocess.check_call([term] + args, stdin=subprocess.PIPE)
                return None
    return "Couldn't start a terminal", 'critical'
