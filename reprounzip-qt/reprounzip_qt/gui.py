# Copyright (C) 2014-2016 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
import yaml

from PyQt4 import QtCore, QtGui

import reprounzip_interface as reprounzip


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


class RunTab(QtGui.QWidget):
    """The main window, that allows you to run/change an unpacked experiment.
    """
    directory = None
    unpacker = None

    def __init__(self, unpacked_directory='', **kwargs):
        super(RunTab, self).__init__(**kwargs)

        layout = QtGui.QGridLayout()
        layout.addWidget(QtGui.QLabel("Experiment directory:"), 0, 0)
        self.directory_widget = QtGui.QLineEdit(unpacked_directory)
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 0, 1)
        browse = QtGui.QPushButton("Browse")
        browse.clicked.connect(self._browse)
        layout.addWidget(browse, 0, 2)

        layout.addWidget(QtGui.QLabel("Unpacker:"), 1, 0,
                         QtCore.Qt.AlignTop)
        self.unpacker_widget = QtGui.QLabel("-")
        layout.addWidget(self.unpacker_widget, 1, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Runs:"), 2, 0,
                         QtCore.Qt.AlignTop)
        self.runs_widget = QtGui.QListWidget(
            selectionMode=QtGui.QListWidget.MultiSelection)
        layout.addWidget(self.runs_widget, 2, 1, 3, 1)
        select_all = QtGui.QPushButton("Select All")
        select_all.clicked.connect(self.runs_widget.selectAll)
        layout.addWidget(select_all, 2, 2)
        deselect_all = QtGui.QPushButton("Deselect All")
        deselect_all.clicked.connect(self.runs_widget.clearSelection)
        layout.addWidget(deselect_all, 3, 2)

        if False:  # TODO
            layout.addWidget(QtGui.QLabel("Input/output files:"), 5, 0,
                             QtCore.Qt.AlignTop)
            files_button = QtGui.QPushButton("(TODO)", enabled=False)
            layout.addWidget(files_button, 5, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("X11 display:"), 6, 0)
        self.x11_enabled = QtGui.QCheckBox("enabled", checked=False)
        layout.addWidget(self.x11_enabled, 6, 1, 1, 2)
        layout.addWidget(QtGui.QLabel("X11 location:"), 7, 0)
        self.x11_display = QtGui.QLineEdit(placeholderText=":0")
        layout.addWidget(self.x11_display, 7, 1, 1, 2)

        layout.setRowStretch(8, 1)

        buttons = QtGui.QHBoxLayout()
        buttons.addStretch(1)
        self.run_widget = QtGui.QPushButton("Run experiment")
        self.run_widget.clicked.connect(self._run)
        buttons.addWidget(self.run_widget)
        self.destroy_widget = QtGui.QPushButton("Destroy unpacked experiment")
        self.destroy_widget.clicked.connect(self._destroy)
        buttons.addWidget(self.destroy_widget)
        layout.addLayout(buttons, 9, 0, 1, 3)

        self.setLayout(layout)

        self._directory_changed()

    def _browse(self):
        picked = QtGui.QFileDialog.getExistingDirectory(
            self, "Pick directory",
            QtCore.QDir.currentPath())
        if picked:
            self.directory_widget.setText(picked)
            self._directory_changed()

    def _directory_changed(self, new_dir=None, force=False):
        if not force and self.directory_widget.text() == self.directory:
            return
        self.directory = self.directory_widget.text()

        unpacker = reprounzip.check_directory(self.directory)

        self.runs_widget.clear()
        if unpacker is not None:
            with open(self.directory + '/config.yml') as fp:
                self.config = yaml.load(fp)
            self.run_widget.setEnabled(True)
            self.destroy_widget.setEnabled(True)
            self.unpacker = unpacker
            self.unpacker_widget.setText(unpacker)
            for run in self.config['runs']:
                self.runs_widget.addItem(' '.join(reprounzip.shell_escape(arg)
                                                  for arg in run['argv']))
            self.runs_widget.selectAll()
        else:
            self.run_widget.setEnabled(False)
            self.destroy_widget.setEnabled(False)
            self.unpacker = None
            self.unpacker_widget.setText("-")

    def _run(self):
        runs = sorted(i.row() for i in self.runs_widget.selectedIndexes())
        error = reprounzip.run(self.directory, runs=runs,
                               unpacker=self.unpacker,
                               x11_enabled=self.x11_enabled.isChecked(),
                               x11_display=self.x11_display.text() or None)
        if error:
            error_msg(self, *error)

    def _destroy(self):
        reprounzip.destroy(self.directory, unpacker=self.unpacker)
        self._directory_changed(force=True)

    def set_directory(self, directory):
        self.directory_widget.setText(directory)
        self._directory_changed()


class UnpackTab(QtGui.QWidget):
    """The unpack window, that sets up a .RPZ file in a directory.
    """
    def __init__(self, package='', **kwargs):
        super(UnpackTab, self).__init__(**kwargs)

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

        layout.addWidget(QtGui.QLabel("GUI (vagrant only)"), 2, 0)
        self.use_gui = QtGui.QCheckBox("enabled", checked=False)
        layout.addWidget(self.use_gui, 2, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Destination directory:"), 3, 0)
        self.directory_widget = QtGui.QLineEdit()
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 3, 1)
        browse_dir = QtGui.QPushButton("Browse")
        browse_dir.clicked.connect(self._browse_dir)
        layout.addWidget(browse_dir, 3, 2)

        layout.setRowStretch(4, 1)

        buttons = QtGui.QHBoxLayout()
        buttons.addStretch(1)
        self.unpack_widget = QtGui.QPushButton("Unpack experiment",
                                               enabled=False)
        self.unpack_widget.clicked.connect(self._unpack)
        buttons.addWidget(self.unpack_widget)
        layout.addLayout(buttons, 5, 0, 1, 3)

        self.setLayout(layout)

        self._package_changed()

    def _browse_pkg(self):
        picked = QtGui.QFileDialog.getOpenFileName(
            self, "Pick package file",
            QtCore.QDir.currentPath(), "ReproZip Packages (*.rpz)")
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
            if os.path.exists(picked):
                error_msg(self, "This directory already exists", 'warning')
            else:
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
            if reprounzip.unpack(self.package_widget.text(),
                                 unpacker.text(),
                                 directory,
                                 use_gui=self.use_gui.isChecked()):
                self.parent().parent().widget(1).set_directory(directory)
                self.parent().parent().setCurrentIndex(1)
            # else: error already seen in terminal
        else:
            error_msg(self, "No unpacker selected", 'warning')


class MainWindow(QtGui.QMainWindow):
    def __init__(self, unpack={}, run={}, tab=None, **kwargs):
        super(MainWindow, self).__init__(**kwargs)

        self.tabs = QtGui.QTabWidget()
        self.tabs.addTab(UnpackTab(**unpack), "Open package")
        self.tabs.addTab(RunTab(**run), "Run unpacked experiment")
        if tab is not None:
            self.tabs.setCurrentIndex(tab)
        self.setCentralWidget(self.tabs)
