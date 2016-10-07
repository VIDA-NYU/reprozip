..  _gui:

ReproUnzip GUI
**************

**reprounzip-qt** is a graphical interface for reprounzip, allowing you to unpack and reproduce experiments from ``.rpz`` files without having to use the command-line. You can also set it as the default handler for the ``.rpz`` file extension so you can open them via double-click.

Installation
============

*reprounzip-qt* comes with the installer on Windows and Mac. If you used one of these, you should be set.

If you are using Anaconda, you can install *reprounzip-qt* from anaconda.org::

    $ conda install --channel vida-nyu reprounzip-qt

Else, you will need to `install PyQt4 <https://www.riverbankcomputing.com/software/pyqt/download>`__ before you can install *reprounzip-qt* from pip (on Debian or Ubuntu, you can use ``apt-get install python-qt4``).

On Linux, setting it as the default to open ``.rpz`` files is a bit more involved. Once the application is setup, `this script <https://gist.github.com/remram44/0092c0b27269cfd0e5530428612d9309>`__ should do the trick.
