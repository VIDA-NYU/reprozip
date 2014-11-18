Installation
************

ReproZip is available as open source, released under the Revised BSD License. Please visit `ReproZip's website <http://vida-nyu.github.io/reprozip/>`_ to find links to our PyPI packages or our `GitHub repository <https://github.com/ViDA-NYU/reprozip>`_.

Software Requirements
=====================

ReproZip is comprised of two components: **reprozip** (for the packing step) and **reprounzip** (for the unpack step). Additional plugins are also provided for *reprounzip*: **reprounzip-vagrant**, which unpacks the experiment in a Vagrant virtual machine, and **reprounzip-docker**, which unpacks the experiment in a Docker container (please see :ref:`unpackers` for more information). More plugins may be developed in the future (and of course, you are free to :ref:`roll your own <develop-plugins>`).

These are all standard Python packages that you can install using pip. However, *reprozip* only works on Linux and needs a C compiler recognized by distutils since it includes a C extension module that will be built during installation.

The operating system compatibility for the ReproZip components is as follows:

+----------------------+----------+--------------+--------------+
| Component            | Linux    | Mac OS X     | Windows      |
+======================+==========+==============+==============+
| *reprozip*           | Yes      | No           | No           |
+----------------------+----------+--------------+--------------+
| *reprounzip*         | Yes      | Yes [#plgn]_ | Yes [#plgn]_ |
+----------------------+----------+--------------+--------------+
| *reprounzip-docker*  | Yes      | No           | No           |
+----------------------+----------+--------------+--------------+
| *reprounzip-vagrant* | Yes      | Yes          | Yes          |
+----------------------+----------+--------------+--------------+

..  [#plgn] The tool works and you can install additional unpackers, but the default bundled unpackers will only work on Linux.

Python 2.7.3 or greater [#bug]_ is required to run ReproZip. If you don't have it yet on your machine, you can get it from `python.org <https://www.python.org/>`_; you should prefer a 2.x releases to 3.x. Besides, depending on the component or plugin to be used, some additional software packages are also required, as described below:

+------------------------------+---------------------------------------------+
| Component / Plugin           | Required Software Packages                  |
+==============================+=============================================+
| *reprozip*                   | `SQLite <http://www.sqlite.org/>`_,         |
|                              | Python headers (python-dev on Debian),      |
|                              | a working C compiler                        |
+------------------------------+---------------------------------------------+
| *reprounzip*                 | None                                        |
+------------------------------+---------------------------------------------+
| *reprounzip-vagrant*         | pycrypto [#pycrypto]_,                      |
|                              | `Vagrant <https://www.vagrantup.com/>`_,    |
|                              | `VirtualBox <https://www.virtualbox.org/>`_ |
+------------------------------+---------------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`_         |
+------------------------------+---------------------------------------------+

..  [#pycrypto] Building PyCrypto on POSIX will require a C compiler and the Python development headers (*python-dev* package on Debian and derived). For installation on Windows without building from source see `here <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`_.
..  [#bug] This is because of `Python bug 13676 <http://bugs.python.org/issue13676>`_ related to sqlite3.

Obtaining the Software
======================

In ReproZip, the components must be installed separately as they fulfill different purposes (and typically, you will use them on different machines). First, you will need Python and `pip <https://pip.pypa.io/en/latest/installing.html>`_. Then, to install a ReproZip component, simply run the following command::

    $ pip install reprozip
    $ # or:
    $ pip install reprounzip

The additional plugins for *reprounzip* can also be installed using the same command, or you can also install all of them using::

    $ pip install reprounzip[all]
