# Copyright (C) 2014-2016 New York University
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

from reprounzip_qt.qt_terminal import run_in_builtin_terminal


safe_shell_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       "-+=/:.,_%")


def shell_escape(s):
    r"""Given bl"a, returns "bl\\"a".
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    if any(c not in safe_shell_chars for c in s):
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
                dct = pickle.load(fp)
            return dct['unpacker']
    return None


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
        x11_enabled=False, root=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    run_in_system_terminal(
        [reprounzip, unpacker, 'run'] +
        (['--enable-x11'] if x11_enabled else []) +
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
        for cmd, arg_factory in [('konsole', lambda a: ['-e', a]),
                                 ('gnome-terminal', lambda a: ['-x', 'a']),
                                 ('lxterminal', lambda a: ['--command=' + a]),
                                 ('rxvt', lambda a: ['-e', a]),
                                 ('xterm', lambda a: ['-e', a])]:
            if find_command(cmd) is not None:
                args = arg_factory(cmd)
                subprocess.check_call([cmd] + args, stdin=subprocess.PIPE)
                return None
    return "Couldn't start a terminal", 'critical'
