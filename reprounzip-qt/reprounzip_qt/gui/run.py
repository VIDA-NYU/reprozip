# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

from qtpy import QtCore, QtWidgets
import yaml
import os

import reprounzip_qt.reprounzip_interface as reprounzip
from reprounzip_qt.gui.common import ROOT, ResizableStack, handle_error, \
    error_msg, parse_ports
from reprounzip_qt.usage import record_usage


class RunOptions(QtWidgets.QWidget):
    x11 = None

    def __init__(self):
        super(RunOptions, self).__init__()
        self.setLayout(QtWidgets.QGridLayout())

    def add_row(self, label, widget):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtWidgets.QLabel(label), row, 0)
        layout.addWidget(widget, row, 1)

    def add_row_layout(self, label, rowlayout):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtWidgets.QLabel(label), row, 0)
        layout.addLayout(rowlayout, row, 1)

    def add_x11(self):
        self.x11 = QtWidgets.QCheckBox("enabled", checked=False)
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
    def __init__(self):
        super(DockerOptions, self).__init__()

        self.x11 = QtWidgets.QCheckBox("enabled", checked=False)
        self.tunneled_x11 = QtWidgets.QCheckBox("use tunnel", checked=False)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.x11)
        row.addWidget(self.tunneled_x11)
        row.addStretch(1)
        self.add_row_layout("X11 display:", row)

        self.detach = QtWidgets.QCheckBox("start background container and "
                                          "leave it running",
                                          checked=False)
        self.add_row("Detach:", self.detach)

        self.raw_options = QtWidgets.QLineEdit('')
        self.add_row("Raw Docker options:", self.raw_options)

        self.ports = QtWidgets.QLineEdit(
            '',
            toolTip="Space-separated host:guest port mappings")
        self.add_row("Expose ports:", self.ports)

    def options(self):
        options = super(DockerOptions, self).options()

        if self.tunneled_x11.isChecked():
            options['args'].append('--tunneled-x11')
            record_usage(docker_tunneled_x11=True)

        if self.detach.isChecked():
            options['args'].append('--detach')
            record_usage(docker_detach=True)

        nb_raw = 0
        for opt in self.raw_options.text().split():
            opt = opt.strip()
            if opt:
                nb_raw += 1
                options['args'].append('--docker-option=%s' % opt)
        if nb_raw:
            record_usage(docker_raw_options=nb_raw)

        ports = parse_ports(self.ports.text(), self)
        if ports is None:
            return None
        for host, container, proto in ports:
            options['args'].extend(
                ['--docker-option=-p',
                 '--docker-option=%s:%s/%s' % (host, container, proto)])
        record_usage(docker_run_port_fwd=bool(ports))

        return options


class VagrantOptions(RunOptions):
    def __init__(self):
        super(VagrantOptions, self).__init__()
        self.add_x11()

        self.ports = QtWidgets.QLineEdit(
            '',
            toolTip="Space-separated host:guest port mappings")
        self.add_row("Expose ports:", self.ports)

    def options(self):
        options = super(VagrantOptions, self).options()

        ports = parse_ports(self.ports.text(), self)
        if ports is None:
            return None
        for host, container, proto in parse_ports(self.ports.text(), self):
            options['args'].append('--expose-port=%s:%s/%s' %
                                   (host, container, proto))
        record_usage(vagrant_run_port_fwd=bool(ports))

        return options


class DataJournalismOptions(RunOptions):
    def __init__(self):
        super(DataJournalismOptions, self).__init__()

        self.rpz = QtWidgets.QLineEdit("")
        self.add_row("RPZ package:", self.rpz)

        self.mode = QtWidgets.QButtonGroup()
        self.record_button = QtWidgets.QRadioButton("record")
        self.mode.addButton(self.record_button)
        self.playback_button = QtWidgets.QRadioButton("playback")
        self.mode.addButton(self.playback_button)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.record_button)
        row.addWidget(self.playback_button)
        row.addStretch(1)
        self.add_row_layout("Mode:", row)

        self.port = QtWidgets.QLineEdit('')
        self.add_row("Webapp port:", self.port)

    def set_rpz(self, directory):
        self.directory = directory
        self.rpz.setText(directory + ".rpz")

    def options(self):
        options = super(DataJournalismOptions, self).options()
        if self.record_button.isChecked():
            options['args'].append('record')
        elif self.playback_button.isChecked():
            options['args'].append('playback')
        else:
            return
        options['args'].append(self.rpz.text())
        options['args'].append(os.path.abspath(self.directory))
        options['args'].append('--port={}'.format(self.port.text()))
        options['args'].append('--skip-setup')

        return options


class FilesManager(QtWidgets.QDialog):
    def __init__(self, directory, unpacker=None, root=None, **kwargs):
        super(FilesManager, self).__init__(**kwargs)
        self.directory = directory
        self.unpacker = unpacker
        self.root = root

        layout = QtWidgets.QHBoxLayout()

        self.files_widget = QtWidgets.QListWidget(
            selectionMode=QtWidgets.QListWidget.SingleSelection)
        self.files_widget.itemSelectionChanged.connect(self._file_changed)
        layout.addWidget(self.files_widget)

        right_layout = QtWidgets.QGridLayout()
        right_layout.addWidget(QtWidgets.QLabel("name:"), 0, 0)
        self.f_name = QtWidgets.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_name, 0, 1)
        right_layout.addWidget(QtWidgets.QLabel("Path:"), 1, 0)
        self.f_path = QtWidgets.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_path, 1, 1)
        right_layout.addWidget(QtWidgets.QLabel("Current:"), 2, 0)
        self.f_status = QtWidgets.QLineEdit('', readOnly=True)
        right_layout.addWidget(self.f_status, 2, 1)
        self.b_upload = QtWidgets.QPushButton("Upload a replacement",
                                              enabled=False)
        self.b_upload.clicked.connect(self._upload)
        right_layout.addWidget(self.b_upload, 3, 0, 1, 2)
        self.b_download = QtWidgets.QPushButton("Download to disk",
                                                enabled=False)
        self.b_download.clicked.connect(self._download)
        right_layout.addWidget(self.b_download, 4, 0, 1, 2)
        self.b_reset = QtWidgets.QPushButton("Reset file", enabled=False)
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
        record_usage(iofiles=self.files_widget.count())

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
                caption = file_status.assigned
                if isinstance(caption, bytes):
                    caption = caption.decode('utf-8', 'replace')
                self.f_status.setText(caption)
                self.f_status.setEnabled(True)

    def _upload(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        picked, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Pick file to upload",
            QtCore.QDir.currentPath())
        if picked:
            record_usage(file_upload=True)
            handle_error(self, reprounzip.upload(
                self.directory, file_status.name, picked,
                unpacker=self.unpacker, root=self.root))
            self._file_changed()

    def _download(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        picked, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Pick destination",
            QtCore.QDir.currentPath() + '/' + file_status.name)
        if picked:
            record_usage(file_download=True)
            handle_error(self, reprounzip.download(
                self.directory, file_status.name, picked,
                unpacker=self.unpacker, root=self.root))
            self._file_changed()

    def _reset(self):
        selected = self.files_widget.selectedIndexes()[0].row()
        file_status = self.files_status[selected]
        record_usage(file_reset=True)
        handle_error(self, reprounzip.upload(
            self.directory, file_status.name, None,
            unpacker=self.unpacker, root=self.root))
        self._file_changed()


class RunTab(QtWidgets.QWidget):
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

        layout = QtWidgets.QGridLayout()
        layout.addWidget(QtWidgets.QLabel("Experiment directory:"), 0, 0)
        self.directory_widget = QtWidgets.QLineEdit(unpacked_directory)
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 0, 1)
        browse = QtWidgets.QPushButton("Browse")
        browse.clicked.connect(self._browse)
        layout.addWidget(browse, 0, 2)

        layout.addWidget(QtWidgets.QLabel("Unpacker:"), 1, 0,
                         QtCore.Qt.AlignTop)
        self.unpacker_widget = QtWidgets.QLabel("-")
        layout.addWidget(self.unpacker_widget, 1, 1, 1, 2)

        layout.addWidget(QtWidgets.QLabel("Input/output files:"), 2, 0,
                         QtCore.Qt.AlignTop)
        self.files_button = QtWidgets.QPushButton("Manage files",
                                                  enabled=False)
        self.files_button.clicked.connect(self._open_files_manager)
        layout.addWidget(self.files_button, 2, 1, 1, 2)

        layout.addWidget(QtWidgets.QLabel("Runs:"), 3, 0,
                         QtCore.Qt.AlignTop)
        self.runs_widget = QtWidgets.QListWidget(
            selectionMode=QtWidgets.QListWidget.MultiSelection)
        layout.addWidget(self.runs_widget, 3, 1, 3, 1)
        select_all = QtWidgets.QPushButton("Select All")
        select_all.clicked.connect(self.runs_widget.selectAll)
        layout.addWidget(select_all, 3, 2)
        deselect_all = QtWidgets.QPushButton("Deselect All")
        deselect_all.clicked.connect(self.runs_widget.clearSelection)
        layout.addWidget(deselect_all, 4, 2)

        layout.addWidget(QtWidgets.QLabel("Elevate privileges:"), 6, 0)
        self.root = QtWidgets.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        layout.addWidget(self.root, 6, 1, 1, 2)

        layout.addWidget(QtWidgets.QLabel("Jupyter integration:"),
                         7, 0)
        self.run_jupyter_notebook = QtWidgets.QCheckBox("Run notebook server",
                                                        checked=False,
                                                        enabled=False)
        layout.addWidget(self.run_jupyter_notebook, 7, 1, 1, 2)

        layout.addWidget(QtWidgets.QLabel("Data Journalism"),
                         8, 0)
        self.data_journalism = QtWidgets.QCheckBox("Data journalism app",
                                                   checked=False,
                                                   enabled=False)
        layout.addWidget(self.data_journalism, 8, 1, 1, 1)
        self.data_journalism.stateChanged.connect(self._toggle_data_journalism_options)

        group = QtWidgets.QGroupBox(title="Unpacker options")
        group_layout = QtWidgets.QVBoxLayout()
        self.unpacker_options = ResizableStack()
        scroll = QtWidgets.QScrollArea(widgetResizable=True)
        scroll.setWidget(self.unpacker_options)
        group_layout.addWidget(scroll)
        group.setLayout(group_layout)
        layout.addWidget(group, 9, 0, 1, 3)
        layout.setRowStretch(9, 1)

        for i, (name, WidgetClass) in enumerate(self.UNPACKERS):
            widget = WidgetClass()
            self.unpacker_options.addWidget(widget)

        self.unpacker_options.addWidget(
            QtWidgets.QLabel("Select a directory to display options..."))
        self.data_journalism_options = DataJournalismOptions()
        self.unpacker_options.addWidget(self.data_journalism_options)
        self.unpacker_options.setCurrentIndex(len(self.UNPACKERS))

        buttons = QtWidgets.QHBoxLayout()
        buttons.addStretch(1)
        self.run_widget = QtWidgets.QPushButton("Run experiment")
        self.run_widget.clicked.connect(self._run)
        buttons.addWidget(self.run_widget)
        self.destroy_widget = QtWidgets.QPushButton("Destroy unpacked "
                                                    "experiment")
        self.destroy_widget.clicked.connect(self._destroy)
        buttons.addWidget(self.destroy_widget)
        layout.addLayout(buttons, 10, 0, 1, 3)

        self.setLayout(layout)

        self._directory_changed()

    def _browse(self):
        picked = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Pick directory",
            QtCore.QDir.currentPath())
        if picked:
            record_usage(browse_unpacked=True)
            self.directory_widget.setText(picked)
            self._directory_changed()

    def _directory_changed(self, new_dir=None, force=False):
        if not force and self.directory_widget.text() == self.directory:
            return
        self.directory = self.directory_widget.text()

        unpacker = reprounzip.check_directory(self.directory)

        self.run_jupyter_notebook.setChecked(False)
        self.run_jupyter_notebook.setEnabled(False)

        self.runs_widget.clear()
        if unpacker is not None:
            with open(self.directory + '/config.yml') as fp:
                self.config = yaml.safe_load(fp)
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

            if (unpacker == 'docker' and
                    reprounzip.find_command('reprozip-jupyter') is not None and
                    reprounzip.is_jupyter(self.directory)):
                self.run_jupyter_notebook.setEnabled(True)
                self.run_jupyter_notebook.setChecked(True)

            if (unpacker == 'docker' and
                    reprounzip.dj_unpacker_installed()):
                self.data_journalism.setEnabled(True)
                self.data_journalism_options.set_rpz(self.directory)

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
        record_usage(run='%d/%d' % (len(runs), self.runs_widget.count()))
        handle_error(self, reprounzip.run(
            self.directory, runs=runs,
            unpacker=self.unpacker,
            root=ROOT.INDEX_TO_OPTION[self.root.currentIndex()],
            jupyter=self.run_jupyter_notebook.isChecked(),
            data_journalism=self.data_journalism.isChecked(),
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
            r = QtWidgets.QMessageBox.question(
                self, "Close Confirmation",
                "The experiment is still unpacked with '%s'. Are you sure you "
                "want to exit without removing it?" % self.unpacker,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if r == QtWidgets.QMessageBox.Yes:
                record_usage(leave_unpacked=True)
                return True
            else:
                return False
        else:
            return True

    def replaceable(self):
        return not self.unpacker

    def _toggle_data_journalism_options(self, checked):
        if checked:
            self._docker_options_index = self.unpacker_options.currentIndex()
            self.unpacker_options.setCurrentIndex(len(self.unpacker_options) - 1)
        elif self._docker_options_index:
            self.unpacker_options.setCurrentIndex(self._docker_options_index)
