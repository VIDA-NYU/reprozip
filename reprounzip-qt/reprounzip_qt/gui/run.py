# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import re
import yaml

from PyQt4 import QtCore, QtGui

import reprounzip_qt.reprounzip_interface as reprounzip
from reprounzip_qt.gui.common import ROOT, ResizableStack, handle_error, \
    error_msg


class RunOptions(QtGui.QWidget):
    x11 = None

    def __init__(self):
        super(RunOptions, self).__init__()
        self.setLayout(QtGui.QGridLayout())

    def add_row(self, label, widget):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtGui.QLabel(label), row, 0)
        layout.addWidget(widget, row, 1)

    def add_row_layout(self, label, rowlayout):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtGui.QLabel(label), row, 0)
        layout.addLayout(rowlayout, row, 1)

    def add_x11(self):
        self.x11 = QtGui.QCheckBox("enabled", checked=False)
        self.add_row("X11 display:", self.x11)

    def options(self):
        options = {'args': []}

        if self.x11 is not None and self.x11.isChecked():
            options['args'].append('--enable-x11')

        return options


class DirectoryOptions(RunOptions):
    def __init__(self):
        super(DirectoryOptions, self).__init__()
        self.add_x11()


class ChrootOptions(RunOptions):
    def __init__(self):
        super(ChrootOptions, self).__init__()
        self.add_x11()


class DockerOptions(RunOptions):
    _port_re = re.compile('^(?:([0-9]+):)?([0-9]+)(?:/([a-z]+))?$')

    def __init__(self):
        super(DockerOptions, self).__init__()

        self.x11 = QtGui.QCheckBox("enabled", checked=False)
        self.tunneled_x11 = QtGui.QCheckBox("use tunnel", checked=False)
        row = QtGui.QHBoxLayout()
        row.addWidget(self.x11)
        row.addWidget(self.tunneled_x11)
        row.addStretch(1)
        self.add_row_layout("X11 display:", row)

        self.detach = QtGui.QCheckBox("start background container and leave "
                                      "it running",
                                      checked=False)
        self.add_row("Detach:", self.detach)

        self.raw_options = QtGui.QLineEdit('')
        self.add_row("Raw Docker options:", self.raw_options)

        self.ports = QtGui.QLineEdit('')
        self.add_row("Publish ports:", self.ports)

    def options(self):
        options = super(DockerOptions, self).options()

        if self.tunneled_x11.isChecked():
            options['args'].append('--tunneled-x11')

        if self.detach.isChecked():
            options['args'].append('--detach')

        for opt in self.raw_options.text().split():
            opt = opt.strip()
            if opt:
                options['args'].append('--docker-option=%s' % opt)

        for port in self.ports.text().split():
            port = port.strip()
            if port:
                m = self._port_re.match(port)
                if m is None:
                    error_msg(self, "Invalid port specification: '%s'" % port,
                              'warning')
                    return None
                else:
                    host, container, proto = m.groups()
                    if not host:
                        host = container
                    if proto:
                        proto = '/' + proto
                    else:
                        proto = ''
                    options['args'].extend(
                        ['--docker-option=-p',
                         '--docker-option=%s:%s%s' % (host, container, proto)])

        return options


class VagrantOptions(RunOptions):
    def __init__(self):
        super(VagrantOptions, self).__init__()
        self.add_x11()


class FilesManager(QtGui.QDialog):
    def __init__(self, directory, unpacker=None, root=None, **kwargs):
        super(FilesManager, self).__init__(**kwargs)
        self.directory = directory
        self.unpacker = unpacker
        self.root = root

        layout = QtGui.QHBoxLayout()

        self.files_widget = QtGui.QListWidget(
            selectionMode=QtGui.QListWidget.SingleSelection)
        self.files_widget.itemSelectionChanged.connect(self._file_changed)
        layout.addWidget(self.files_widget)

        right_layout = QtGui.QGridLayout()
        right_layout.addWidget(QtGui.QLabel("name:"), 0, 0)
        self.f_name = QtGui.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_name, 0, 1)
        right_layout.addWidget(QtGui.QLabel("Path:"), 1, 0)
        self.f_path = QtGui.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_path, 1, 1)
        right_layout.addWidget(QtGui.QLabel("Current:"), 2, 0)
        self.f_status = QtGui.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_status, 2, 1)
        self.b_upload = QtGui.QPushButton("Upload a replacement",
                                          enabled=False)
        self.b_upload.clicked.connect(self._upload)
        right_layout.addWidget(self.b_upload, 3, 0, 1, 2)
        self.b_download = QtGui.QPushButton("Download to disk", enabled=False)
        self.b_download.clicked.connect(self._download)
        right_layout.addWidget(self.b_download, 4, 0, 1, 2)
        self.b_reset = QtGui.QPushButton("Reset file", enabled=False)
        self.b_reset.clicked.connect(self._reset)
        right_layout.addWidget(self.b_reset, 5, 0, 1, 2)
        right_layout.setRowStretch(6, 1)
        layout.addLayout(right_layout)

        self.setLayout(layout)

        self.files_status = reprounzip.FilesStatus(directory)

        for file_status in self.files_status:
            text = "[%s%s] %s" % (("I" if file_status.is_input else ''),
                                  ("O" if file_status.is_output else ''),
                                  file_status.name)
            self.files_widget.addItem(text)

    def _file_changed(self):
        selected = [i.row() for i in self.files_widget.selectedIndexes()]
        if not selected:
            self.f_name.setText('')
            self.f_path.setText('')
            self.f_status.setText('')
            self.b_upload.setEnabled(False)
            self.b_download.setEnabled(False)
            self.b_reset.setEnabled(False)
        else:
            file_status = self.files_status[selected[0]]
            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
            self.b_reset.setEnabled(False)
            self.f_name.setText(file_status.name)
            self.f_path.setText(file_status.path)
            self.f_status.setEnabled(False)
            if file_status.assigned is None:
                self.f_status.setText("(original)")
                self.b_reset.setEnabled(False)
            elif file_status.assigned is False:
                self.f_status.setText("(not created)")
            elif file_status.assigned is True:
                self.f_status.setText("(generated)")
            else:
                self.f_status.setText(file_status.assigned)
                self.f_status.setEnabled(True)

    def _upload(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        picked = QtGui.QFileDialog.getOpenFileName(
            self, "Pick file to upload",
            QtCore.QDir.currentPath())
        if picked:
            handle_error(self, reprounzip.upload(
                self.directory, file_status.name, picked,
                unpacker=self.unpacker, root=self.root))
            self._file_changed()

    def _download(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        picked = QtGui.QFileDialog.getSaveFileName(
            self, "Pick destination",
            QtCore.QDir.currentPath() + '/' + file_status.name)
        if picked:
            handle_error(self, reprounzip.download(
                self.directory, file_status.name, picked,
                unpacker=self.unpacker, root=self.root))
            self._file_changed()

    def _reset(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        handle_error(self, reprounzip.upload(
            self.directory, file_status.name, None,
            unpacker=self.unpacker, root=self.root))
        self._file_changed()


class RunTab(QtGui.QWidget):
    """The main window, that allows you to run/change an unpacked experiment.
    """
    UNPACKERS = [
        ('directory', DirectoryOptions),
        ('chroot', ChrootOptions),
        ('docker', DockerOptions),
        ('vagrant', VagrantOptions),
    ]

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

        layout.addWidget(QtGui.QLabel("Input/output files:"), 2, 0,
                         QtCore.Qt.AlignTop)
        self.files_button = QtGui.QPushButton("Manage files", enabled=False)
        self.files_button.clicked.connect(self._open_files_manager)
        layout.addWidget(self.files_button, 2, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Runs:"), 3, 0,
                         QtCore.Qt.AlignTop)
        self.runs_widget = QtGui.QListWidget(
            selectionMode=QtGui.QListWidget.MultiSelection)
        layout.addWidget(self.runs_widget, 3, 1, 3, 1)
        select_all = QtGui.QPushButton("Select All")
        select_all.clicked.connect(self.runs_widget.selectAll)
        layout.addWidget(select_all, 3, 2)
        deselect_all = QtGui.QPushButton("Deselect All")
        deselect_all.clicked.connect(self.runs_widget.clearSelection)
        layout.addWidget(deselect_all, 4, 2)

        layout.addWidget(QtGui.QLabel("Elevate privileges:"), 6, 0)
        self.root = QtGui.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        layout.addWidget(self.root, 6, 1, 1, 2)

        group = QtGui.QGroupBox(title="Unpacker options")
        group_layout = QtGui.QVBoxLayout()
        self.unpacker_options = ResizableStack()
        scroll = QtGui.QScrollArea(widgetResizable=True)
        scroll.setWidget(self.unpacker_options)
        group_layout.addWidget(scroll)
        group.setLayout(group_layout)
        layout.addWidget(group, 7, 0, 1, 3)
        layout.setRowStretch(7, 1)

        for i, (name, WidgetClass) in enumerate(self.UNPACKERS):
            widget = WidgetClass()
            self.unpacker_options.addWidget(widget)

        self.unpacker_options.addWidget(QtGui.QLabel("Select an directory to "
                                                     "display options..."))
        self.unpacker_options.setCurrentIndex(len(self.UNPACKERS))

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
            self.files_button.setEnabled(True)
            self.unpacker = unpacker
            self.unpacker_widget.setText(unpacker)
            for run in self.config['runs']:
                self.runs_widget.addItem(' '.join(reprounzip.shell_escape(arg)
                                                  for arg in run['argv']))
            self.runs_widget.selectAll()
            self.unpacker_options.setCurrentIndex(
                dict((n, i) for i, (n, w) in enumerate(self.UNPACKERS))
                .get(unpacker, 4))
        else:
            self.run_widget.setEnabled(False)
            self.destroy_widget.setEnabled(False)
            self.files_button.setEnabled(False)
            self.unpacker = None
            self.unpacker_widget.setText("-")
            self.unpacker_options.setCurrentIndex(len(self.UNPACKERS))

    def _run(self):
        options = self.unpacker_options.currentWidget().options()
        if options is None:
            return
        runs = sorted(i.row() for i in self.runs_widget.selectedIndexes())
        if not runs:
            error_msg(self, "No run selected", 'warning')
            return
        handle_error(self, reprounzip.run(
            self.directory, runs=runs,
            unpacker=self.unpacker,
            root=ROOT.INDEX_TO_OPTION[self.root.currentIndex()],
            **options))

    def _destroy(self):
        handle_error(self, reprounzip.destroy(
            self.directory, unpacker=self.unpacker,
            root=ROOT.INDEX_TO_OPTION[self.root.currentIndex()]))
        self._directory_changed(force=True)

    def _open_files_manager(self):
        manager = FilesManager(
            parent=self,
            directory=self.directory_widget.text(),
            unpacker=self.unpacker,
            root=ROOT.INDEX_TO_OPTION[self.root.currentIndex()])
        manager.exec_()

    def set_directory(self, directory, root=None):
        self.root.setCurrentIndex(ROOT.OPTION_TO_INDEX[root])
        self.directory_widget.setText(directory)
        self._directory_changed(force=True)

    def should_exit(self):
        if self.unpacker:
            r = QtGui.QMessageBox.question(
                self, "Close Confirmation",
                "The experiment is still unpacked with '%s'. Are you sure you "
                "want to exit without removing it?" % self.unpacker,
                QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
            return r == QtGui.QMessageBox.Yes
        else:
            return True
