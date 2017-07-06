# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
import platform
from PyQt4 import QtCore, QtGui
import shutil
import subprocess
import sys
import tempfile
import traceback

import reprounzip_qt
from reprounzip_qt.gui.common import error_msg
from reprounzip_qt.gui.unpack import UnpackTab
from reprounzip_qt.gui.run import RunTab


class Application(QtGui.QApplication):
    def __init__(self, argv):
        QtGui.QApplication.__init__(self, argv)
        self.first_window = None
        self.windows = set()

    def linux_try_register_default(self, window):
        rcpath = os.path.expanduser('~/.reprozip')
        rcname = 'rpuzqt-nodefault'
        if os.path.exists(os.path.join(rcpath, rcname)):
            return
        try:
            proc = subprocess.Popen(['xdg-mime', 'query', 'default',
                                     'application/x-reprozip'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            out, err = proc.communicate()
            registered = bool(out.strip())
        except OSError:
            pass
        else:
            if not registered:
                r = QtGui.QMessageBox.question(
                    window, "Default application",
                    "Do you want to set ReproUnzip as the default to open "
                    ".rpz files?",
                    QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
                if r == QtGui.QMessageBox.Yes:
                    self.linux_register_default(window)
                elif r == QtGui.QMessageBox.No:
                    if not os.path.exists(rcpath):
                        os.mkdir(rcpath)
                    with open(os.path.join(rcpath, rcname), 'w') as fp:
                        fp.write('1\n')

    def linux_register_default(self, window):
        command = os.path.abspath(sys.argv[0])
        if not os.path.isfile(command):
            return
        dirname = tempfile.mkdtemp(prefix='reprozip_mime_')
        try:
            # Install x-reprozip mimetype
            filename = os.path.join(dirname, 'nyuvida-reprozip.xml')
            with open(filename, 'w') as fp:
                fp.write('''\
<?xml version="1.0"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-reprozip">
    <comment>ReproZip Package</comment>
    <glob pattern="*.rpz"/>
  </mime-type>
</mime-info>
''')
            subprocess.check_call(['xdg-mime', 'install', filename])
            subprocess.check_call(['update-mime-database',
                                   os.path.join(os.environ['HOME'],
                                                '.local/share/mime')])

            # Install desktop file
            app_dir = os.path.join(os.environ['HOME'],
                                   '.local/share/applications')
            if not os.path.exists(app_dir):
                os.makedirs(app_dir)
            with open(os.path.join(app_dir, 'reprounzip.desktop'), 'w') as fp:
                fp.write('''\
[Desktop Entry]
Name=ReproUnzip
Exec={0} %f
Type=Application
MimeType=application/x-reprozip
'''.format(command))
            subprocess.check_call(['update-desktop-database', app_dir])

            # Install icon
            iconpath = os.path.join(os.environ['HOME'],
                                    '.local/share/icons/hicolor')
            icondir = os.path.join(iconpath, '48x48/mimetypes')
            iconfile = os.path.join(os.path.dirname(reprounzip_qt.__file__),
                                    'icon.png')
            if not os.path.exists(icondir):
                os.makedirs(icondir)
            shutil.copyfile(
                iconfile,
                os.path.join(icondir, 'application-x-reprozip.png'))
            subprocess.check_call(['update-icon-caches', iconpath])
        except (OSError, subprocess.CalledProcessError):
            error_msg(window, "Error setting default application",
                      'error', traceback.format_exc())
        finally:
            shutil.rmtree(dirname)

    def event(self, event):
        if event.type() == QtCore.QEvent.FileOpen:
            # Create new window for this RPZ
            window = ReprounzipUi(unpack=dict(package=event.file()))
            window.setVisible(True)
            self.windows.add(window)
            # Close first window if it exists
            if self.first_window and self.first_window.replaceable():
                self.first_window.close()
                self.first_window.deleteLater()
                self.first_window = None
            return True
        return QtGui.QApplication.event(self, event)

    def set_first_window(self, window):
        self.first_window = window
        self.windows.add(window)
        if platform.system().lower() == 'linux':
            self.linux_try_register_default(window)


class ReprounzipUi(QtGui.QMainWindow):
    def __init__(self, unpack={}, run={}, tab=None, **kwargs):
        super(ReprounzipUi, self).__init__(**kwargs)

        self.tabs = QtGui.QTabWidget()
        self.tabs.addTab(UnpackTab(**unpack), "Open package")
        self.tabs.addTab(RunTab(**run), "Run unpacked experiment")
        self.tabs.widget(0).unpacked.connect(self._unpacked)
        if tab is not None:
            self.tabs.setCurrentIndex(tab)
        self.setCentralWidget(self.tabs)

    def _unpacked(self, directory, root):
        self.tabs.widget(1).set_directory(directory, root=root)
        self.tabs.setCurrentIndex(1)

    def closeEvent(self, event):
        if self.tabs.widget(1).should_exit():
            Application.instance().windows.discard(self)
            event.accept()
        else:
            event.ignore()

    def replaceable(self):
        return (self.tabs.widget(0).replaceable() and
                self.tabs.widget(1).replaceable())
