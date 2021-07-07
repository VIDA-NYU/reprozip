# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import os
from qtpy import QtCore, QtWidgets
import subprocess
import sys

import reprounzip_qt.reprounzip_interface as reprounzip
from reprounzip_qt.gui.common import ROOT, ResizableStack, \
    handle_error, error_msg, parse_ports
from reprounzip_qt.usage import record_usage


class UnpackerOptions(QtWidgets.QWidget):
    def __init__(self):
        super(UnpackerOptions, self).__init__()
        self.setLayout(QtWidgets.QGridLayout())

    def add_row(self, label, widget):
        layout = self.layout()
        row = layout.rowCount()
        layout.addWidget(QtWidgets.QLabel(label), row, 0)
        layout.addWidget(widget, row, 1)

    def options(self):
        return {'args': []}

    @staticmethod
    def available():
        return True


class DirectoryOptions(UnpackerOptions):
    def __init__(self):
        super(DirectoryOptions, self).__init__()
        self.layout().addWidget(
            QtWidgets.QLabel("(directory unpacker has no option)"),
            0, 0, 1, 2)

    @staticmethod
    def available():
        return sys.platform.startswith('linux')


class ChrootOptions(UnpackerOptions):
    def __init__(self):
        super(ChrootOptions, self).__init__()

        self.root = QtWidgets.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        self.add_row("Elevate privileges:", self.root)

        self.preserve_owner = QtWidgets.QCheckBox("enabled", tristate=True)
        self.preserve_owner.setCheckState(QtCore.Qt.PartiallyChecked)
        self.add_row("Preserve file ownership:", self.preserve_owner)

        self.magic_dirs = QtWidgets.QCheckBox(
            "mount /dev and /proc inside the chroot", tristate=True)
        self.magic_dirs.setCheckState(QtCore.Qt.PartiallyChecked)
        self.add_row("Mount magic dirs:", self.magic_dirs)

    def options(self):
        options = super(ChrootOptions, self).options()

        options['root'] = ROOT.INDEX_TO_OPTION[self.root.currentIndex()]

        if self.preserve_owner.checkState() == QtCore.Qt.Unchecked:
            options['args'].append('--dont-preserve-owner')
        elif self.preserve_owner.checkState() == QtCore.Qt.Checked:
            options['args'].append('--preserve-owner')

        if self.magic_dirs.checkState() == QtCore.Qt.Unchecked:
            options['args'].append('--dont-bind-magic-dirs')
        elif self.magic_dirs.checkState() == QtCore.Qt.Checked:
            options['args'].append('--bind-magic-dirs')

        record_usage(
            chroot_preserve_owner=self.preserve_owner.checkState(),
            chroot_magic_dirs=self.magic_dirs.checkState())

        return options

    @staticmethod
    def available():
        return sys.platform.startswith('linux')


class DockerOptions(UnpackerOptions):
    def __init__(self):
        super(DockerOptions, self).__init__()

        self.root = QtWidgets.QComboBox(editable=False)
        self.root.addItems(ROOT.TEXT)
        self.add_row("Elevate privileges:", self.root)

        try:
            cmd = ['docker-machine', 'ls', '-q']
            query = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            out, _ = query.communicate()
            if query.returncode != 0:
                raise subprocess.CalledProcessError(query.returncode, cmd)
            self.machine = QtWidgets.QComboBox(editable=False)
            if 'DOCKER_HOST' in os.environ:
                self.machine.addItem("Custom config from environment", None)
            else:
                self.machine.addItem("Default (no machine)", None)
            nb_machines = 0
            for machine in out.splitlines():
                machine = machine.strip()
                if machine:
                    self.machine.addItem(machine.decode('utf-8', 'replace'),
                                         machine)
                    nb_machines += 1
            record_usage(docker_machines=nb_machines)
        except (OSError, subprocess.CalledProcessError):
            self.machine = QtWidgets.QComboBox(editable=False, enabled=False)
            self.machine.addItem("docker-machine unavailable", None)
            record_usage(docker_machines=False)
        self.add_row("docker-machine:", self.machine)

        self.image = QtWidgets.QLineEdit(placeholderText='detect')
        self.add_row("Base image:", self.image)

        self.distribution = QtWidgets.QLineEdit(placeholderText='detect')
        self.add_row("Distribution:", self.distribution)

        self.install_pkgs = QtWidgets.QCheckBox("install packages rather than "
                                                "extracting them from RPZ")
        self.add_row("Install packages:", self.install_pkgs)

    def options(self):
        options = super(DockerOptions, self).options()

        if self.machine.currentIndex() != -1:
            options['docker-machine'] = self.machine.itemData(
                self.machine.currentIndex())
            record_usage(
                use_docker_machine=options['docker-machine'] is not None)

        options['root'] = ROOT.INDEX_TO_OPTION[self.root.currentIndex()]

        if self.image.text():
            options['args'].extend(['--base-image', self.image.text()])
            record_usage(docker_base_image=True)

        if self.distribution.text():
            options['args'].extend(['--distribution',
                                    self.distribution.text()])
            record_usage(docker_distribution=True)

        if self.install_pkgs.isChecked():
            options['args'].append('--install-pkgs')

        record_usage(root=options['root'],
                     docker_install_pkgs=self.install_pkgs.isChecked())

        return options


class VagrantOptions(UnpackerOptions):
    def __init__(self):
        super(VagrantOptions, self).__init__()

        self.image = QtWidgets.QLineEdit(placeholderText='detect')
        self.add_row("Base box:", self.image)

        self.distribution = QtWidgets.QLineEdit(placeholderText='detect')
        self.add_row("Distribution:", self.distribution)

        self.memory = QtWidgets.QSpinBox(suffix="MB",
                                         minimum=99, maximum=64000, value=99,
                                         specialValueText="(default)")
        self.add_row("Memory:", self.memory)

        self.gui = QtWidgets.QCheckBox("Enable local GUI")
        self.add_row("GUI:", self.gui)

        self.ports = QtWidgets.QLineEdit(
            '',
            toolTip="Space-separated host:guest port mappings")
        self.add_row("Expose ports:", self.ports)

        self.use_chroot = QtWidgets.QCheckBox(
            "use chroot and prefer packed files over the virtual machines' "
            "files",
            checked=True)
        self.add_row("Chroot:", self.use_chroot)

        self.magic_dirs = QtWidgets.QCheckBox("mount /dev and /proc inside "
                                              "the chroot", checked=True)
        self.add_row("Mount magic dirs:", self.magic_dirs)

    def options(self):
        options = super(VagrantOptions, self).options()

        if self.image.text():
            options['args'].extend(['--base-image', self.image.text()])
            record_usage(vagrant_base_image=True)

        if self.distribution.text():
            options['args'].extend(['--distribution',
                                    self.distribution.text()])
            record_usage(vagrant_distribution=True)

        if self.memory.value() != 99:
            options['args'].extend(['--memory', '%d' % self.memory.value()])
            record_usage(vagrant_memory=self.memory.value())

        if self.gui.isChecked():
            options['args'].append('--use-gui')
            record_usage(vagrant_gui=True)

        ports = parse_ports(self.ports.text(), self)
        if ports is None:
            return None
        record_usage(vagrant_unpack_port_fwd=bool(ports))
        for host, container, proto in ports:
            options['args'].append('--expose-port=%s:%s/%s' % (
                                   host, container, proto))

        if not self.use_chroot.isChecked():
            options['args'].append('--dont-use-chroot')
            record_usage(vagrant_no_chroot=True)

        if not self.magic_dirs.isChecked():
            options['args'].append('--dont-bind-magic-dirs')
            record_usage(vagrant_magic_dirs=False)

        return options


class UnpackTab(QtWidgets.QWidget):
    """The unpack window, that sets up a .RPZ file in a directory.
    """
    UNPACKERS = [
        ('directory', DirectoryOptions),
        ('chroot', ChrootOptions),
        ('docker', DockerOptions),
        ('vagrant', VagrantOptions),
    ]

    unpacked = QtCore.Signal(str, object)

    def __init__(self, package='', **kwargs):
        super(UnpackTab, self).__init__(**kwargs)

        layout = QtWidgets.QGridLayout()
        layout.addWidget(QtWidgets.QLabel("RPZ package:"), 0, 0)
        self.package_widget = QtWidgets.QLineEdit(package, enabled=False)
        layout.addWidget(self.package_widget, 0, 1)
        browse_pkg = QtWidgets.QPushButton("Browse")
        browse_pkg.clicked.connect(self._browse_pkg)
        layout.addWidget(browse_pkg, 0, 2)

        layout.addWidget(QtWidgets.QLabel("Unpacker:"), 1, 0,
                         QtCore.Qt.AlignTop)
        ulayout = QtWidgets.QVBoxLayout()
        self.unpackers = QtWidgets.QButtonGroup()
        for i, (name, opts) in enumerate(self.UNPACKERS):
            radio = QtWidgets.QRadioButton(name)
            radio.unpacker = name
            self.unpackers.addButton(radio, i)
            ulayout.addWidget(radio)
            if not opts.available():
                radio.setDisabled(True)
        layout.addLayout(ulayout, 1, 1, 1, 2)

        group = QtWidgets.QGroupBox(title="Unpacker options")
        group_layout = QtWidgets.QVBoxLayout()
        self.unpacker_options = ResizableStack()
        self.unpackers.buttonClicked[int].connect(
            self.unpacker_options.setCurrentIndex)
        scroll = QtWidgets.QScrollArea(widgetResizable=True)
        scroll.setWidget(self.unpacker_options)
        group_layout.addWidget(scroll)
        group.setLayout(group_layout)
        layout.addWidget(group, 2, 0, 1, 3)
        layout.setRowStretch(2, 1)

        for i, (name, WidgetClass) in enumerate(self.UNPACKERS):
            widget = WidgetClass()
            self.unpacker_options.addWidget(widget)

        self.unpacker_options.addWidget(
            QtWidgets.QLabel("Select an unpacker to display options..."))
        self.unpacker_options.setCurrentIndex(len(self.UNPACKERS))

        layout.addWidget(QtWidgets.QLabel("Destination directory:"), 3, 0)
        self.directory_widget = QtWidgets.QLineEdit()
        self.directory_widget.editingFinished.connect(self._directory_changed)
        layout.addWidget(self.directory_widget, 3, 1)
        browse_dir = QtWidgets.QPushButton("Browse")
        browse_dir.clicked.connect(self._browse_dir)
        layout.addWidget(browse_dir, 3, 2)

        buttons = QtWidgets.QHBoxLayout()
        buttons.addStretch(1)
        self.unpack_widget = QtWidgets.QPushButton("Unpack experiment",
                                                   enabled=False)
        self.unpack_widget.clicked.connect(self._unpack)
        buttons.addWidget(self.unpack_widget)
        layout.addLayout(buttons, 4, 0, 1, 3)

        self.setLayout(layout)

        self._package_changed()

    def replaceable(self):
        return not self.package_widget.text()

    def _browse_pkg(self):
        picked, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Pick package file",
            QtCore.QDir.currentPath(), "ReproZip Packages (*.rpz)")
        if picked:
            record_usage(browse_pkg=True)
            self.package_widget.setText(picked)
            self._package_changed()

    def _package_changed(self, new_pkg=None):
        package = self.package_widget.text()
        if package.lower().endswith('.rpz'):
            self.directory_widget.setText(package[:-4])
            self._directory_changed()

    def _browse_dir(self):
        picked, _ = QtWidgets.QFileDialog.getSaveFileName(
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
            record_usage(unpacker=unpacker.text())
            options = self.unpacker_options.currentWidget().options()
            if options is None:
                return
            if handle_error(self, reprounzip.unpack(
                    self.package_widget.text(),
                    unpacker.unpacker,
                    directory,
                    options)):
                self.unpacked.emit(os.path.abspath(directory),
                                   options.get('root'))
        else:
            error_msg(self, "No unpacker selected", 'warning')
