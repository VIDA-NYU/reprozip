# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from qtpy import QtCore, QtWidgets
import re


def error_msg(parent, message, severity, details=None):
    if severity == 'information':
        icon = QtWidgets.QMessageBox.Information
    elif severity == 'warning':
        icon = QtWidgets.QMessageBox.Warning
    else:
        icon = QtWidgets.QMessageBox.Critical

    msgbox = QtWidgets.QMessageBox(icon, "Error", message,
                                   QtWidgets.QMessageBox.Ok, parent,
                                   detailedText=details,
                                   textFormat=QtCore.Qt.PlainText)
    msgbox.exec_()


def handle_error(parent, result):
    if result in (True, False):
        return result
    else:
        error_msg(parent, *result)
        return False


class ResizableStack(QtWidgets.QStackedWidget):
    # See http://stackoverflow.com/a/14485901/711380
    def __init__(self, **kwargs):
        super(ResizableStack, self).__init__(**kwargs)

        self.currentChanged[int].connect(self._current_changed)

    def addWidget(self, widget):
        widget.setSizePolicy(QtWidgets.QSizePolicy.Ignored,
                             QtWidgets.QSizePolicy.Ignored)
        super(ResizableStack, self).addWidget(widget)

    def _current_changed(self, idx):
        widget = self.widget(idx)
        widget.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                             QtWidgets.QSizePolicy.Expanding)
        widget.adjustSize()
        self.adjustSize()


class ROOT(object):
    OPTION_TO_INDEX = {None: 0, 'sudo': 1, 'su': 2}
    INDEX_TO_OPTION = {0: None, 1: 'sudo', 2: 'su'}
    TEXT = ["no", "with sudo", "with su"]


_port_re = re.compile('^(?:([0-9]+):)?([0-9]+)(?:/([a-z]+))?$')


def parse_ports(string, widget):
    ports = []

    for port in string.split():
        port = port.strip()
        if not port:
            continue

        m = _port_re.match(port)
        if m is None:
            error_msg(widget, "Invalid port specification: '%s'" % port,
                      'warning')
            return None
        else:
            host, experiment, proto = m.groups()
            if not host:
                host = experiment
            if not proto:
                proto = 'tcp'
            ports.append((int(host), int(experiment), proto))

    return ports
