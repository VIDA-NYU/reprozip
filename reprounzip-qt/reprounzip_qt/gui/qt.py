import os


def _get_qt():
    qtapi = os.environ.get('QT_API')

    # Try PyQt4
    if qtapi is None or qtapi == 'pyqt' or qtapi == 'pyqt4':
        try:
            import PyQt4  # noqa
            import sip
        except ImportError:
            pass
        else:
            api2_classes = [
                'QData', 'QDateTime', 'QString', 'QTextStream',
                'QTime', 'QUrl', 'QVariant'
            ]
            for cl in api2_classes:
                try:
                    sip.setapi(cl, 2)
                except ValueError:
                    pass
            from PyQt4 import QtCore
            from PyQt4 import QtGui

            os.environ['QT_API'] = 'pyqt'

            return QtCore, QtGui, QtGui, 'pyqt4'

    # Try PyQt5
    if qtapi is None or qtapi == 'pyqt5':
        try:
            import PyQt5  # noqa
        except ImportError:
            pass
        else:
            from PyQt5 import QtCore
            from PyQt5 import QtGui
            from PyQt5 import QtWidgets

            os.environ['QT_API'] = 'pyqt5'

            return QtCore, QtGui, QtWidgets, 'pyqt5'

    # Oh no
    raise ImportError("Couldn't import PyQt4 or PyQt5")


__all__ = ['QtCore', 'QtGui', 'QtWidgets', 'QT_API']


QtCore, QtGui, QtWidgets, QT_API = _get_qt()
