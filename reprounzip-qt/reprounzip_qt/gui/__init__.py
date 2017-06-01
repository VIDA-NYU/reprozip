# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from PyQt4 import QtCore, QtGui

from reprounzip_qt.gui.unpack import UnpackTab
from reprounzip_qt.gui.run import RunTab


class Application(QtGui.QApplication):
    def __init__(self, argv):
        QtGui.QApplication.__init__(self, argv)
        self.main_window = None

    def event(self, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if self.main_window:
                self.main_window.open_rpz(event.file())
                return True
        return QtGui.QApplication.event(self, event)

    def set_main_window(self, window):
        self.main_window = window


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
            event.accept()
        else:
            event.ignore()

    def open_rpz(self, filename):
        if self.tabs.widget(1).should_exit():
            self.tabs.widget(0).change_package(filename)
            self.tabs.setCurrentIndex(0)
