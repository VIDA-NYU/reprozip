Installation
************

ReproZip is available as open source, released under the Revised BSD License. The tool is comprised of two components: **reprozip** (for the packing step) and **reprounzip** (for the unpack step). Additional plugins are also provided for *reprounzip*: **reprounzip-vagrant**, which unpacks the experiment in a Vagrant virtual machine, and **reprounzip-docker**, which unpacks the experiment in a Docker container; more plugins may be developed in the future (and, of course, you are free to :ref:`roll your own <develop-plugins>`).
In our `website <http://vida-nyu.github.io/reprozip/>`__, you can find links to our PyPI packages and our `GitHub repository <https://github.com/ViDA-NYU/reprozip>`__.

In the following, you will find installation instructions for :ref:`linux`, :ref:`mac`, and :ref:`windows`. ReproZip is also available for the :ref:`conda` Python distribution.

..  _linux:

Linux
=====

For Linux distributions, both *reprozip* and *reprounzip* components are available.

Required Software Packages
--------------------------

Python 2.7.3 or greater is recommended to run ReproZip. Older versions should allow *reprounzip* to work, but some features will not be available [#bug]_. If you don't have Python on your machine, you can get it from `python.org <https://www.python.org/>`__ [#deb]_; you should prefer a 2.x release to a 3.x one. You will also need the `pip <https://pip.pypa.io/en/latest/installing.html>`__ installer.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+-----------------------------------------------+
| Component / Plugin           | Required Software Packages                    |
+==============================+===============================================+
| *reprozip*                   | `SQLite <http://www.sqlite.org/>`__ [#deb2]_, |
|                              | Python headers [#deb3]_,                      |
|                              | a working C compiler                          |
+------------------------------+-----------------------------------------------+
| *reprounzip*                 | None                                          |
+------------------------------+-----------------------------------------------+
| *reprounzip-vagrant*         | Python headers [#deb3]_ [#pycrypton]_,        |
|                              | a working C compiler [#pycrypton]_,           |
|                              | `Vagrant 1.1+ <https://www.vagrantup.com/>`__,|
|                              | `VirtualBox <https://www.virtualbox.org/>`__  |
+------------------------------+-----------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`__          |
+------------------------------+-----------------------------------------------+

..  [#bug] ``reprounzip graph`` will not work due to `Python bug 13676 <http://bugs.python.org/issue13676>`__ related to sqlite3.
..  [#deb] On Debian and Debian-based, you can use ``sudo apt-get install python``.
..  [#deb2] On Debian and Debian-based, you can use ``sudo apt-get install libsqlite3-dev``.
..  [#deb3] On Debian and Debian-based, you can use ``sudo apt-get install python-dev``.
..  [#pycrypton] Required to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`__.

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

    $ pip install reprounzip-docker reprounzip-vagrant

Alternatively, you can install *reprounzip* with all the available plugins using::

    $ pip install reprounzip[all]

..  _mac:

Mac OS X
========

For Mac OS X, only the *reprounzip* component is available.

Binaries
--------

An installer containing Python 2.7, *reprounzip*, and all the plugins can be `downloaded from GitHub <https://github.com/ViDA-NYU/reprozip/releases/download/0.6/reprounzip-0.6.pkg>`__.

Required Software Packages
--------------------------

Python 2.7.3 or greater is recommended to run ReproZip. Older versions should allow *reprounzip* to work, but some features will not be available [#bug2]_. If you don't have Python on your machine, you can get it from `python.org <https://www.python.org/>`__; you should prefer a 2.x release to a 3.x one. You will also need the `pip <https://pip.pypa.io/en/latest/installing.html>`__ installer.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+-----------------------------------------------+
| Component / Plugin           | Required Software Packages                    |
+==============================+===============================================+
| *reprounzip*                 | None                                          |
+------------------------------+-----------------------------------------------+
| *reprounzip-vagrant*         | Python headers [#macn]_ [#pycrypton2]_,       |
|                              | a working C compiler [#macn]_ [#pycrypton2]_, |
|                              | `Vagrant 1.1+ <https://www.vagrantup.com/>`__,|
|                              | `VirtualBox <https://www.virtualbox.org/>`__  |
+------------------------------+-----------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`__          |
+------------------------------+-----------------------------------------------+

..  [#bug2] ``reprounzip graph`` will not work due to `Python bug 13676 <http://bugs.python.org/issue13676>`__ related to sqlite3.
..  [#macn] This is usually provided by installing Xcode (in the Mac App Store) and the Command Line Developer Tools; instructions on installing the latter may depend on your Mac OS X version (some information on StackOverflow `here <http://stackoverflow.com/questions/9329243/xcode-4-4-and-later-install-command-line-tools?answertab=active#tab-top>`__).
..  [#pycrypton2] Required to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`__.

..  seealso:: :ref:`compiler_mac`

Installing *reprounzip*
-----------------------

First, be sure to upgrade `setuptools`::

    $ pip install -U setuptools

To install the *reprounzip* component, simply run the following command::

    $ pip install reprounzip

To update the software, use the flag ``-U``::

    $ pip install -U reprounzip

The additional plugins for *reprounzip* can also be installed using the same command::

    $ pip install reprounzip-docker reprounzip-vagrant

Alternatively, you can install *reprounzip* with all the available plugins using::

    $ pip install reprounzip[all]

..  _windows:

Windows
=======

For Windows, only the *reprounzip* component is available.

Binaries
--------

A 32-bit installer containing Python 2.7, *reprounzip*, and all the plugins can be `downloaded from GitHub <https://github.com/ViDA-NYU/reprozip/releases/download/0.6/reprounzip-0.6-setup.exe>`__.

Required Software Packages
--------------------------

Python 2.7.3 or greater is recommended to run ReproZip. Older versions should allow *reprounzip* to work, but some features will not be available [#bug3]_. If you don't have Python on your machine, you can get it from `python.org <https://www.python.org/>`__; you should prefer a 2.x release to a 3.x one. You will also need the `pip <https://pip.pypa.io/en/latest/installing.html>`__ installer.

Besides Python and pip, each component or plugin to be used may have additional dependencies that you need to install (if you do not have them already installed in your environment), as described below:

+------------------------------+------------------------------------------------------------------------+
| Component / Plugin           | Required Software Packages                                             |
+==============================+========================================================================+
| *reprounzip*                 | None                                                                   |
+------------------------------+------------------------------------------------------------------------+
| *reprounzip-vagrant*         | `PyCrypto <https://www.dlitz.net/software/pycrypto/>`__ [#pycrypton3]_,|
|                              | `Vagrant 1.1+ <https://www.vagrantup.com/>`__,                         |
|                              | `VirtualBox <https://www.virtualbox.org/>`__                           |
+------------------------------+------------------------------------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`__                                   |
+------------------------------+------------------------------------------------------------------------+

..  [#bug3] ``reprounzip graph`` will not work due to `Python bug 13676 <http://bugs.python.org/issue13676>`__ related to sqlite3.
..  [#pycrypton3] A working C compiler is required to build PyCrypto. For installation without building from source, please see `this page <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`__.

..  seealso:: :ref:`pycrypto_windows`

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

..  _conda:

Anaconda
========

*reprozip* and *reprounzip* can also be installed on the `Anaconda <https://store.continuum.io/cshop/anaconda>`__ Python distribution, from Binstar::

    $ conda install -c https://conda.binstar.org/vida-nyu reprozip reprounzip reprounzip-docker reprounzip-vagrant

Note, however, that *reprozip* is only available for Linux.
