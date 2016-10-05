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
                self.b_download.setEnabled(False)
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

        layout.addWidget(QtGui.QLabel("Input/output files:"), 5, 0,
                         QtCore.Qt.AlignTop)
        self.files_button = QtGui.QPushButton("Manage files", enabled=False)
        self.files_button.clicked.connect(self._open_files_manager)
        layout.addWidget(self.files_button, 5, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("Elevate privileges:"), 6, 0)
        self.root = QtGui.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        layout.addWidget(self.root, 6, 1, 1, 2)

        layout.addWidget(QtGui.QLabel("X11 display:"), 7, 0)
        self.x11_enabled = QtGui.QCheckBox("enabled", checked=False)
        layout.addWidget(self.x11_enabled, 7, 1, 1, 2)

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
            self.files_button.setEnabled(True)
            self.unpacker = unpacker
            self.unpacker_widget.setText(unpacker)
            for run in self.config['runs']:
                self.runs_widget.addItem(' '.join(reprounzip.shell_escape(arg)
                                                  for arg in run['argv']))
            self.runs_widget.selectAll()
        else:
            self.run_widget.setEnabled(False)
            self.destroy_widget.setEnabled(False)
            self.files_button.setEnabled(False)
            self.unpacker = None
            self.unpacker_widget.setText("-")

    def _run(self):
        runs = sorted(i.row() for i in self.runs_widget.selectedIndexes())
        handle_error(self, reprounzip.run(
            self.directory, runs=runs,
            unpacker=self.unpacker,
            x11_enabled=self.x11_enabled.isChecked(),
            root=ROOT.INDEX_TO_OPTION[self.root.currentIndex()]))

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
        self._directory_changed()


class UnpackerOptions(QtGui.QWidget):
    def __init__(self):
        super(UnpackerOptions, self).__init__()
        self.setLayout(QtGui.QGridLayout())

    def add_row(self, label, widget):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtGui.QLabel(label), row, 0)
        layout.addWidget(widget, row, 1)


class DirectoryOptions(UnpackerOptions):
    def __init__(self):
        super(DirectoryOptions, self).__init__()
        self.layout().addWidget(
            QtGui.QLabel("(directory unpacker has no option)"),
            0, 0, 1, 2)

    def options(self):
        return {}


class ChrootOptions(UnpackerOptions):
    def __init__(self):
        super(ChrootOptions, self).__init__()

        self.root = QtGui.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        self.add_row("Elevate privileges:", self.root)

        self.preserve_owner = QtGui.QCheckBox("enabled", tristate=True)
        self.preserve_owner.setCheckState(QtCore.Qt.PartiallyChecked)
        self.add_row("Preserve file ownership:", self.preserve_owner)

        self.magic_dirs = QtGui.QCheckBox(
            "mount /dev and /proc inside the chroot", tristate=True)
        self.magic_dirs.setCheckState(QtCore.Qt.PartiallyChecked)
        self.add_row("Mount magic dirs:", self.magic_dirs)

    def options(self):
        options = {'args': []}

        options['root'] = ROOT.INDEX_TO_OPTION[self.root.currentIndex()]

        if self.preserve_owner.checkState() == QtCore.Qt.Unchecked:
            options['args'].append('--dont-preserve-owner')
        elif self.preserve_owner.checkState() == QtCore.Qt.Checked:
            options['args'].append('--preserve-owner')

        if self.magic_dirs.checkState() == QtCore.Qt.Unchecked:
            options['args'].append('--dont-bind-magic-dirs')
        elif self.magic_dirs.checkState() == QtCore.Qt.Checked:
            options['args'].append('--bind-magic-dirs')

        return options


class DockerOptions(UnpackerOptions):
    def __init__(self):
        super(DockerOptions, self).__init__()

        self.root = QtGui.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        self.add_row("Elevate privileges:", self.root)

        self.image = QtGui.QLineEdit(placeholderText='detect')
        self.add_row("Base image:", self.image)

        self.distribution = QtGui.QLineEdit(placeholderText='detect')
        self.add_row("Distribution:", self.distribution)

        self.install_pkgs = QtGui.QCheckBox("install packages rather than "
                                            "extracting them from RPZ")
        self.add_row("Install packages:", self.install_pkgs)

    def options(self):
        options = {'args': []}

        options['root'] = ROOT.INDEX_TO_OPTION[self.root.currentIndex()]

        if self.image.text():
            options['args'].extend(['--base-image', self.image.text()])

        if self.distribution.text():
            options['args'].extend(['--distribution',
                                    self.distribution.text()])

        if self.install_pkgs.isChecked():
            options['args'].append('--install-pkgs')

        return options


class VagrantOptions(UnpackerOptions):
    def __init__(self):
        super(VagrantOptions, self).__init__()

        self.image = QtGui.QLineEdit(placeholderText='detect')
        self.add_row("Base box:", self.image)

        self.distribution = QtGui.QLineEdit(placeholderText='detect')
        self.add_row("Distribution:", self.distribution)

        self.memory = QtGui.QSpinBox(suffix="MB", minimum=99, maximum=64000,
                                     specialValueText="(default)", value=99)
        self.add_row("Memory:", self.memory)

        self.gui = QtGui.QCheckBox("Enable local GUI")
        self.add_row("GUI:", self.gui)

        self.use_chroot = QtGui.QCheckBox("use chroot and prefer packed files "
                                          "over the virtual machines' files",
                                          checked=True)
        self.add_row("Chroot:", self.use_chroot)

        self.magic_dirs = QtGui.QCheckBox("mount /dev and /proc inside the "
                                          "chroot", checked=True)
        self.add_row("Mount magic dirs:", self.magic_dirs)

    def options(self):
        options = {'args': []}

        if self.image.text():
            options['args'].extend(['--base-image', self.image.text()])

        if self.distribution.text():
            options['args'].extend(['--distribution',
                                    self.distribution.text()])

        if self.memory.value() != 99:
            options['args'].extend(['--memory', '%d' % self.memory.value()])

        if self.gui.isChecked():
            options['args'].append('--use-gui')

        if not self.use_chroot.isChecked():
            options['args'].append('--dont-use-chroot')

        if not self.magic_dirs.isChecked():
            options['args'].append('--dont-bind-magic-dirs')

        return options


class UnpackTab(QtGui.QWidget):
    """The unpack window, that sets up a .RPZ file in a directory.
    """
    UNPACKERS = [
        ('directory', DirectoryOptions),
        ('chroot', ChrootOptions),
        ('docker', DockerOptions),
        ('vagrant', VagrantOptions),
    ]

    unpacked = QtCore.pyqtSignal(str, object)

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
        for i, name in enumerate(n for n, c in self.UNPACKERS):
            radio = QtGui.QRadioButton(name)
            self.unpackers.addButton(radio, i)
            ulayout.addWidget(radio)
        layout.addLayout(ulayout, 1, 1, 1, 2)

        group = QtGui.QGroupBox(title="Unpacker options")
        group_layout = QtGui.QVBoxLayout()
        self.unpacker_options = ResizableStack()
        self.unpackers.buttonClicked[int].connect(
            self.unpacker_options.setCurrentIndex)
        scroll = QtGui.QScrollArea(widgetResizable=True)
        scroll.setWidget(self.unpacker_options)
        group_layout.addWidget(scroll)
        group.setLayout(group_layout)
        layout.addWidget(group, 2, 0, 1, 3)
        layout.setRowStretch(2, 1)

        for i, (name, WidgetClass) in enumerate(self.UNPACKERS):
            widget = WidgetClass()
            self.unpacker_options.addWidget(widget)

        self.unpacker_options.addWidget(QtGui.QLabel("Select an unpacker to "
                                                     "display options..."))
        self.unpacker_options.setCurrentIndex(len(self.UNPACKERS))

        layout.addWidget(QtGui.QLabel("Destination directory:"), 3, 0)
        self.directory_widget = QtGui.QLineEdit()
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 3, 1)
        browse_dir = QtGui.QPushButton("Browse")
        browse_dir.clicked.connect(self._browse_dir)
        layout.addWidget(browse_dir, 3, 2)

        buttons = QtGui.QHBoxLayout()
        buttons.addStretch(1)
        self.unpack_widget = QtGui.QPushButton("Unpack experiment",
                                               enabled=False)
        self.unpack_widget.clicked.connect(self._unpack)
        buttons.addWidget(self.unpack_widget)
        layout.addLayout(buttons, 4, 0, 1, 3)

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
            options = self.unpacker_options.currentWidget().options()
            if handle_error(self, reprounzip.unpack(
                    self.package_widget.text(),
                    unpacker.text(),
                    directory,
                    options)):
                self.unpacked.emit(os.path.abspath(directory),
                                   options.get('root'))
        else:
            error_msg(self, "No unpacker selected", 'warning')


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
