# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from PyQt4 import QtCore, QtGui


def error_msg(parent, message, severity, details=None):
    if severity == 'information':
        icon = QtGui.QMessageBox.Information
    elif severity == 'warning':
        icon = QtGui.QMessageBox.Warning
    else:
        icon = QtGui.QMessageBox.Critical

    msgbox = QtGui.QMessageBox(icon, "Error", message, QtGui.QMessageBox.Ok,
                               parent, detailedText=details,
                               textFormat=QtCore.Qt.PlainText)
    msgbox.exec_()


def handle_error(parent, result):
    if result in (True, False):
        return result
    else:
        error_msg(parent, *result)
        return False


class ResizableStack(QtGui.QStackedWidget):
    # See http://stackoverflow.com/a/14485901/711380
    def __init__(self, **kwargs):
        super(ResizableStack, self).__init__(**kwargs)

        self.currentChanged[int].connect(self._current_changed)

    def addWidget(self, widget):
        widget.setSizePolicy(QtGui.QSizePolicy.Ignored,
                             QtGui.QSizePolicy.Ignored)
        super(ResizableStack, self).addWidget(widget)

    def _current_changed(self, idx):
        widget = self.widget(idx)
        widget.setSizePolicy(QtGui.QSizePolicy.Expanding,
                             QtGui.QSizePolicy.Expanding)
        widget.adjustSize()
        self.adjustSize()


class ROOT(object):
    OPTION_TO_INDEX = {None: 0, 'sudo': 1, 'su': 2}
    INDEX_TO_OPTION = {0: None, 1: 'sudo', 2: 'su'}
    TEXT = ["no", "with sudo", "with su"]
