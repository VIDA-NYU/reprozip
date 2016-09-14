# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from PyQt4 import QtCore, QtGui

import reprounzip_interface as reprounzip


def createComboBox(initial_text=''):
    box = QtGui.QComboBox(editable=True)
    box.addItem(initial_text)
    box.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
    return box


def error_msg(parent, message, severity='critical'):
    if severity == 'information':
        msgbox = QtGui.QMessageBox.information
    elif severity == 'warning':
        msgbox = QtGui.QMessageBox.warning
    else:
        msgbox = QtGui.QMessageBox.critical

    msgbox(parent, "Error", message)


class RunWindow(QtGui.QDialog):
    """The main window, that allows you to run/change an unpacked experiment.
    """
    directory = None
    unpacker = None

    def __init__(self, unpacked_directory='', **kwargs):
        super(RunWindow, self).__init__(**kwargs)

        layout = QtGui.QGridLayout()
        layout.addWidget(QtGui.QLabel("Experiment directory:"), 0, 0)
        self.directory_widget = createComboBox(unpacked_directory)
        self.directory_widget.lineEdit().editingFinished.connect(
            self._directory_changed)
        self.directory_widget.currentIndexChanged[str].connect(
            self._directory_changed)
        layout.addWidget(self.directory_widget, 0, 1)
        browse = QtGui.QPushButton("Browse")
        browse.clicked.connect(self._browse)
        layout.addWidget(browse, 0, 2)

        unpack = QtGui.QPushButton("Unpack .rpz file")
        unpack.clicked.connect(self._unpack)
        layout.addWidget(unpack, 1, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Unpacker:"), 2, 0,
                         QtCore.Qt.AlignTop)
        self.unpacker_widget = QtGui.QLabel("-")
        layout.addWidget(self.unpacker_widget, 2, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Runs:"), 3, 0,
                         QtCore.Qt.AlignTop)
        layout.addWidget(QtGui.QLabel("(TODO)"), 3, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Input/output files:"), 4, 0,
                         QtCore.Qt.AlignTop)
        layout.addWidget(QtGui.QLabel("(TODO)"), 4, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("X11 display:"), 5, 0)
        self.x11_enabled = QtGui.QCheckBox("enabled", checked=False)
        layout.addWidget(self.x11_enabled, 5, 1, 1, 2)
        layout.addWidget(QtGui.QLabel("X11 location:"), 6, 0)
        self.x11_display = QtGui.QLineEdit(placeholderText=":0")
        layout.addWidget(self.x11_display, 6, 1, 1, 2)

        layout.setRowStretch(7, 1)

        buttons = QtGui.QHBoxLayout()
        buttons.addStretch(1)
        self.run_widget = QtGui.QPushButton("Run experiment")
        self.run_widget.clicked.connect(self._run)
        buttons.addWidget(self.run_widget)
        self.destroy_widget = QtGui.QPushButton("Destroy unpacked experiment")
        self.destroy_widget.clicked.connect(self._destroy)
        buttons.addWidget(self.destroy_widget)
        layout.addLayout(buttons, 8, 0, 1, 3)

        self.setLayout(layout)

        self._directory_changed()

    def _browse(self):
        picked = QtGui.QFileDialog.getExistingDirectory(
            self, "Pick directory",
            QtCore.QDir.currentPath())
        if picked:
            self.directory_widget.setEditText(picked)
            self._directory_changed()

    def _directory_changed(self, new_dir=None, force=False):
        if not force and self.directory_widget.currentText() == self.directory:
            return
        self.directory = self.directory_widget.currentText()

        unpacker = reprounzip.check_directory(self.directory)

        if unpacker is not None:
            if unpacker == 'directory':
                self.unpackers.button(0).click()
            self.run_widget.setEnabled(True)
            self.destroy_widget.setEnabled(True)
            self.unpacker = unpacker
            self.unpacker_widget.setText(unpacker)
        else:
            self.run_widget.setEnabled(False)
            self.destroy_widget.setEnabled(False)
            self.unpacker = None
            self.unpacker_widget.setText("-")

    def _unpack(self):
        unpacked_out = []
        dialog = UnpackWindow(parent=self, unpacked_out=unpacked_out)
        if dialog.exec_():
            self.directory_widget.setEditText(unpacked_out[0])
            self._directory_changed()

    def _run(self):
        error = reprounzip.run(self.directory, unpacker=self.unpacker)
        if error:
            error_msg(self, *error)

    def _destroy(self):
        error = reprounzip.destroy(self.directory, unpacker=self.unpacker)
        if error:
            error_msg(self, *error)
        self._directory_changed(force=True)


class UnpackWindow(QtGui.QDialog):
    """The unpack window, that sets up a .RPZ file in a directory.
    """
    def __init__(self, package='', unpacked_out=None, **kwargs):
        super(UnpackWindow, self).__init__(**kwargs)

        self.unpacked_out = unpacked_out

        layout = QtGui.QGridLayout()
        layout.addWidget(QtGui.QLabel("RPZ package:"), 0, 0)
        self.package_widget = QtGui.QLineEdit(package, enabled=False)
        layout.addWidget(self.package_widget, 0, 1)
        browse_pkg = QtGui.QPushButton("Browse")
        browse_pkg.clicked.connect(self._browse_pkg)
        layout.addWidget(browse_pkg, 0, 2)

        layout.addWidget(QtGui.QLabel("Unpacker:"), 1, 0,
                         QtCore.Qt.AlignTop)
        ulayout = QtGui.QVBoxLayout()
        self.unpackers = QtGui.QButtonGroup()
        for i, name in enumerate(['directory', 'chroot', 'docker', 'vagrant']):
            radio = QtGui.QRadioButton(name)
            self.unpackers.addButton(radio, i)
            ulayout.addWidget(radio)
        layout.addLayout(ulayout, 1, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Destination directory:"), 2, 0)
        self.directory_widget = QtGui.QLineEdit()
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 2, 1)
        browse_dir = QtGui.QPushButton("Browse")
        browse_dir.clicked.connect(self._browse_dir)
        layout.addWidget(browse_dir, 2, 2)

        layout.setRowStretch(3, 1)

        buttons = QtGui.QHBoxLayout()
        buttons.addStretch(1)
        self.unpack_widget = QtGui.QPushButton("Unpack experiment",
                                               enabled=False)
        self.unpack_widget.clicked.connect(self._unpack)
        buttons.addWidget(self.unpack_widget)
        cancel_widget = QtGui.QPushButton("Cancel")
        cancel_widget.clicked.connect(self.reject)
        buttons.addWidget(cancel_widget)
        layout.addLayout(buttons, 4, 0, 1, 3)

        self.setLayout(layout)

        self._package_changed()

    def _browse_pkg(self):
        picked = QtGui.QFileDialog.getOpenFileName(
            self, "Pick package file",
            QtCore.QDir.currentPath())
        if picked:
            self.package_widget.setText(picked)
            self._package_changed()

    def _package_changed(self, new_pkg=None):
        package = self.package_widget.text()
        if package.lower().endswith('.rpz'):
            self.directory_widget.setText(package[:-4])
            self._directory_changed()

    def _browse_dir(self):
        picked = QtGui.QFileDialog.getSaveFileName(
            self, "Pick directory",
            QtCore.QDir.currentPath())
        if picked:
            self.directory_widget.setText(picked)
            self._directory_changed()

    def _directory_changed(self, new_dir=None):
        self.unpack_widget.setEnabled(bool(self.directory_widget.text()))

    def _unpack(self):
        directory = self.directory_widget.text()
        if not directory:
            return
        unpacker = self.unpackers.checkedButton()
        if unpacker:
            error = reprounzip.unpack(self.package_widget.text(),
                                      unpacker.text(),
                                      directory)
        else:
            error = "No unpacker selected", 'warning'
        if error:
            error_msg(self, *error)
        else:
            if self.unpacked_out is not None:
                self.unpacked_out[:] = [directory]
            else:
                RunWindow(unpacked_directory=directory).setVisible(True)
            self.accept()