Installation
************

ReproZip is available as open source, released under the Revised BSD License. The tool is comprised of two components: **reprozip** (for the packing step) and **reprounzip** (for the unpack step). Additional plugins are also provided for *reprounzip*: **reprounzip-vagrant**, which unpacks the experiment in a Vagrant virtual machine, and **reprounzip-docker**, which unpacks the experiment in a Docker container; more plugins may be developed in the future (and, of course, you are free to :ref:`roll your own <develop-plugins>`).
In our `website <http://vida-nyu.github.io/reprozip/>`_, you can find links to our PyPI packages and our `GitHub repository <https://github.com/ViDA-NYU/reprozip>`_.

In the following, you will find installation instructions for :ref:`linux`, :ref:`mac`, and :ref:`windows`.

.. _linux:

Linux
=====

For Linux distributions, both *reprozip* and *reprounzip* components are available.

Required Software Packages
--------------------------

Python 2.7.3 or greater [#bug]_ is **required** to run ReproZip. If you don't have it yet on your machine, you can get it from `python.org <https://www.python.org/>`_ [#deb]_; you should prefer a 2.x releases to 3.x. You will also need `pip <https://pip.pypa.io/en/latest/installing.html>`_.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+---------------------------------------------+
| Component / Plugin           | Required Software Packages                  |
+==============================+=============================================+
| *reprozip*                   | `SQLite <http://www.sqlite.org/>`_ [#deb2]_,|
|                              | Python headers [#deb3]_,                    |
|                              | a working C compiler                        |
+------------------------------+---------------------------------------------+
| *reprounzip*                 | None                                        |
+------------------------------+---------------------------------------------+
| *reprounzip-vagrant*         | Python headers [#deb3]_ [#pycrypton]_,      |
|                              | a working C compiler [#pycrypton]_,         |
|                              | `Vagrant <https://www.vagrantup.com/>`_,    |
|                              | `VirtualBox <https://www.virtualbox.org/>`_ |
+------------------------------+---------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`_         |
+------------------------------+---------------------------------------------+

..  [#bug] Due to `Python bug 13676 <http://bugs.python.org/issue13676>`_ related to sqlite3.
..  [#deb] On Debian and Debian-based, this is provided by *python*: ``sudo apt-get install python``.
..  [#deb2] On Debian and Debian-based, this is provided by *libsqlite3-dev*: ``sudo apt-get install libsqlite3-dev``.
..  [#deb3] On Debian and Debian-based, this is provided by *python-dev*: ``sudo apt-get install python-dev``.
..  [#pycrypton] Required to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_.

Installing *reprozip*
---------------------

To install the *reprozip* component, simply run the following command::

    $ pip install reprozip

To update the software, use the flag ``-U``::

    $ pip install -U reprozip

Installing *reprounzip*
-----------------------

To install the *reprounzip* component, simply run the following command::

    $ pip install reprounzip

To update the software, use the flag ``-U``::

    $ pip install -U reprounzip

The additional plugins for *reprounzip* can also be installed using the same command::

    $ pip install reprounzip-vagrant
    $ pip install reprounzip-docker

Alternatively, you can install *reprounzip* with all the available plugins using::

    $ pip install reprounzip[all]

.. _mac:

Mac OS X
========

For Mac OS X, only the *reprounzip* component is available.

Binaries
--------

Comming soon!

Required Software Packages
--------------------------

Python 2.7.3 or greater [#bug2]_ is **required** to run ReproZip. If you don't have it yet on your machine, you can get it from `python.org <https://www.python.org/>`_; you should prefer a 2.x releases to 3.x. You will also need `pip <https://pip.pypa.io/en/latest/installing.html>`_.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+----------------------------------------------+
| Component / Plugin           | Required Software Packages                   |
+==============================+==============================================+
| *reprounzip*                 | None                                         |
+------------------------------+----------------------------------------------+
| *reprounzip-vagrant*         | Python headers [#macn]_ [#pycrypton2]_,      |
|                              | a working C compiler [#macn]_ [#pycrypton2]_,|
|                              | `Vagrant <https://www.vagrantup.com/>`_,     |
|                              | `VirtualBox <https://www.virtualbox.org/>`_  |
+------------------------------+----------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`_          |
+------------------------------+----------------------------------------------+

..  [#bug2] Due to `Python bug 13676 <http://bugs.python.org/issue13676>`_ related to sqlite3.
..  [#macn] This is usually provided by installing Xcode (in the Mac App Store) and the Command Line Developer Tools; instructions on installing the latter may depend on your Mac OS X version (some information on StackOverflow `here <http://stackoverflow.com/questions/9329243/xcode-4-4-and-later-install-command-line-tools?answertab=active#tab-top>`_).
..  [#pycrypton2] Required to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_.

.. seealso:: :ref:`compiler_mac`

Installing *reprounzip*
-----------------------

First, upgrade `setuptools`::

    $ pip install -U setuptools

To install the *reprounzip* component, simply run the following command::

    $ pip install reprounzip

To update the software, use the flag ``-U``::

    $ pip install -U reprounzip

The additional plugins for *reprounzip* can also be installed using the same command::

    $ pip install reprounzip-vagrant
    $ pip install reprounzip-docker

Alternatively, you can install *reprounzip* with all the available plugins using::

    $ pip install reprounzip[all]

.. _windows:

Windows
=======

For Windows, only the *reprounzip* component is available.

Binaries
--------

Comming soon!

Required Software Packages
--------------------------

Python 2.7.3 or greater [#bug3]_ is **required** to run ReproZip. If you don't have it yet on your machine, you can get it from `python.org <https://www.python.org/>`_; you should prefer a 2.x releases to 3.x. You will also need `pip <https://pip.pypa.io/en/latest/installing.html>`_.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+------------------------------------------------------------------------+
| Component / Plugin           | Required Software Packages                                             |
+==============================+========================================================================+
| *reprounzip*                 | None                                                                   |
+------------------------------+------------------------------------------------------------------------+
| *reprounzip-vagrant*         | `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_ [#pycrypton3]_, |
|                              | `Vagrant <https://www.vagrantup.com/>`_,                               |
|                              | `VirtualBox <https://www.virtualbox.org/>`_                            |
+------------------------------+------------------------------------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`_                                    |
+------------------------------+------------------------------------------------------------------------+

..  [#bug3] Due to `Python bug 13676 <http://bugs.python.org/issue13676>`_ related to sqlite3.
..  [#pycrypton3] A working C compiler is required to build PyCrypto. For installation without building from source, please see `this page <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`_.

.. seealso:: :ref:`pycrypto_windows`

Installing *reprounzip*
-----------------------

To install the *reprounzip* component, simply run the following command::

    $ pip install reprounzip

To update the software, use the flag ``-U``::

    $ pip install -U reprounzip

The additional plugins for *reprounzip* can also be installed using the same command::

    $ pip install reprounzip-vagrant
    $ pip install reprounzip-docker

Alternatively, you can install *reprounzip* with all the available plugins using::

    $ pip install reprounzip[all]

