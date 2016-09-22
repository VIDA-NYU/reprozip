# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
import pickle
import platform
import subprocess

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


def check_directory(directory):
    if os.path.isdir(directory):
        filename = os.path.join(directory, '.reprounzip')
        if os.path.isfile(filename):
            with open(filename, 'rb') as fp:
                dct = pickle.load(fp)
            return dct['unpacker']
    return None


def find_command(cmd):
    for path in os.environ.get('PATH', '').split(os.pathsep):
        filename = os.path.join(path, cmd)
        if os.path.exists(filename):
            return filename
    return None


def run(directory, unpacker=None, runs=None,
        x11_enabled=False, x11_display=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    reprounzip = find_command('reprounzip')
    if reprounzip is None:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    run_in_system_terminal(
        [shell_escape(reprounzip), unpacker, 'run'] +
        (['--docker-option=-p', '--docker-option=8000:8000']
         if unpacker == 'docker' else []) +
        (['--enable-x11'] if x11_enabled else []) +
        (['--x11-display', x11_display] if x11_display is not None else []) +
        [shell_escape(directory)] +
        ([','.join('%d' % r for r in runs)] if runs is not None else []))


def unpack(package, unpacker, directory, use_gui=False):
    code = run_in_builtin_terminal(
        ['reprounzip', unpacker, 'setup'] +
        (['--use-gui'] if use_gui and unpacker == 'vagrant' else []) +
        [package, directory],
        text="Unpacking experiment...",
        success_msg="Successfully setup experiment",
        fail_msg="Error setting up experiment")
    return code == 0


def destroy(directory, unpacker=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    code = run_in_builtin_terminal(
        ['reprounzip', unpacker, 'destroy', directory],
        text="Destroying experiment directory...",
        success_msg="Successfully destroyed experiment directory",
        fail_msg="Error destroying experiment")
    return code == 0


def run_in_system_terminal(cmd, wait=True, close_on_success=False):
    cmd = ' '.join(shell_escape(c) for c in cmd)

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
