# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
import pickle
import platform
import subprocess

safe_shell_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       "-+=/:.,%_")


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


def check_directory(directory):
    if os.path.isdir(directory):
        filename = os.path.join(directory, '.reprounzip')
        if os.path.isfile(filename):
            with open(filename, 'rb') as fp:
                dct = pickle.load(fp)
            return dct['unpacker']
    return None


def run(directory, unpacker=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    for path in os.environ.get('PATH', '').split(os.pathsep):
        reprounzip = os.path.join(path, 'reprounzip')
        if os.path.exists(reprounzip):
            break
    else:
        return ("Couldn't find reprounzip command -- is reprounzip installed?",
                'critical')

    _run_in_terminal('%s %s run %s' % (
        shell_escape(reprounzip), unpacker, shell_escape(directory)))


def _run_in_terminal(cmd):
    system = platform.system().lower()
    if system == 'darwin':
        proc = subprocess.Popen(['/usr/bin/osascript', '-'],
                                stdin=subprocess.PIPE)
        proc.communicate("""\
tell application "Terminal"
    activate
    set w to do script %s
    repeat
        delay 1
        if not busy of w then exit repeat
    end repeat
    (*activate
    tell (first window whose tabs contain w)
        set selected tab to w
        tell application "System Events"
            tell process "Terminal"
                keystroke "w" using {command down}
            end tell
        end tell
    end tell*)
end tell
""" % shell_escape(cmd + ';exit'))
        proc.wait()
    else:
        return "Couldn't start a terminal", 'critical'
    return None


def destroy(directory, unpacker=None):
    if unpacker is None:
        unpacker = check_directory(directory)

    proc = subprocess.Popen(['reprounzip', unpacker, 'destroy', directory],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()

    if proc.returncode == 0:
        return None
    else:
        return "Error destroying experiment:\n%s" % out, 'critical'


def unpack(package, unpacker, directory):
    proc = subprocess.Popen(['reprounzip', unpacker, 'setup',
                             package, directory],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()

    if proc.returncode == 0:
        return None
    else:
        return "Error setting up experiment:\n%s" % out, 'critical'
