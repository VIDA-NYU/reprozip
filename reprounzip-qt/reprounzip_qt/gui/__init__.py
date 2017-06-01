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
        self.first_window = None
        self.windows = set()

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
