# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division, print_function, unicode_literals

import locale
import logging
from qtpy import QtCore, QtWidgets
import sys


if sys.version_info >= (3,):
    from html import escape
else:
    from cgi import escape


logger = logging.getLogger('reprounzip_qt')


class Terminal(QtWidgets.QWidget):
    finished = QtCore.Signal(int)

    def __init__(self, cmdline, env, input_enabled=False,
                 success_msg=None, fail_msg=None,
                 **kwargs):
        super(Terminal, self).__init__(**kwargs)

        self.success_msg = success_msg or "Command finished"
        self.fail_msg = fail_msg or "Command failed"

        layout = QtWidgets.QVBoxLayout()
        self.text = QtWidgets.QTextEdit(readOnly=True)
        layout.addWidget(self.text)
        if input_enabled:
            self.input = QtWidgets.QLineEdit()
            self.input.returnPressed.connect(self._enter)
            layout.addWidget(self.input)
        else:
            self.input = None
        self.setLayout(layout)

        self.process = QtCore.QProcess(self)

        # Dodge py2app issues
        environ = QtCore.QProcessEnvironment.systemEnvironment()
        if environ.contains('PYTHONHOME'):
            environ.remove('PYTHONPATH')
            environ.remove('PYTHONHOME')
        if sys.platform == 'darwin':
            environ.insert(
                'PATH',
                (environ.value('PATH', '/usr/bin:/bin:/usr/sbin:/sbin') +
                 ':/usr/local/bin:/opt/reprounzip'))

        # Unset TERM to avoid ansi escapes
        environ.remove('TERM')

        # Add additional environment variables
        for k, v in env.items():
            environ.insert(k, v)

        logger.info("Running in builtin Qt terminal: %r", cmdline)

        self.process.setProcessEnvironment(environ)
        self.process.setProcessChannelMode(QtCore.QProcess.SeparateChannels)
        if input_enabled:
            mode = QtCore.QIODevice.ReadWrite
        else:
            mode = QtCore.QIODevice.ReadOnly
        self.process.start(cmdline[0], cmdline[1:], mode)
        if not input_enabled:
            self.process.closeWriteChannel()
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.text.setHtml('''\
<style>
body {
    font: Consolas, "Liberation Mono", Menlo, Courier, monospace;
}

.err {
    color: red;
}
</style>
''')
        self.text.append('<span style="color: blue;">%s</span>' %
                         escape(' '.join(cmdline)))

    def _enter(self):
        cmd = self.input.text()
        self.input.setText('')
        self.process.write(cmd + '\n')

    def _read_stdout(self):
        out = self.process.readAllStandardOutput()
        out = bytes(out).decode(locale.getpreferredencoding() or 'UTF-8',
                                'replace')
        self.text.append('<span>%s</span>' % escape(out))

    def _read_stderr(self):
        out = self.process.readAllStandardError()
        out = bytes(out).decode(locale.getpreferredencoding() or 'UTF-8',
                                'replace')
        self.text.append('<span class="err">%s</span>' % escape(out))

    def _finished(self, code, status):
        good = False
        if status == QtCore.QProcess.NormalExit:
            msg = "returned %d" % code
            self.finished.emit(code)
            good = code == 0
        else:
            msg = "crashed"
            self.finished.emit(-1)
        if good:
            msg = self.success_msg
        else:
            msg = "%s (%s)" % (self.fail_msg, msg)
        self.text.append('<br><span style="color: blue;">%s</span>' % msg)


def run_in_builtin_terminal(cmd, env,
                            text=None, success_msg=None, fail_msg=None):
    result = [False]

    def store_result(code):
        result[:] = [code]

    dialog = QtWidgets.QDialog()
    layout = QtWidgets.QVBoxLayout()
    if text is not None:
        layout.addWidget(QtWidgets.QLabel(text))
    terminal = Terminal(cmd, env, input_enabled=False,
                        success_msg=success_msg, fail_msg=fail_msg)
    terminal.finished.connect(store_result)
    layout.addWidget(terminal)
    buttons = QtWidgets.QHBoxLayout()
    buttons.addStretch(1)
    accept = QtWidgets.QPushButton("Close", enabled=False)
    accept.clicked.connect(dialog.accept)
    terminal.finished.connect(lambda _: accept.setEnabled(True))
    buttons.addWidget(accept)
    layout.addLayout(buttons)
    dialog.setLayout(layout)
    dialog.exec_()

    return result[0]
