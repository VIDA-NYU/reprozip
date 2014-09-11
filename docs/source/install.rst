Installation
************

ReproZip is available as open source, released under the Revised BSD License. Please visit `ReproZip's website <http://vida-nyu.github.io/reprozip/>`_ to find links to our PyPI packages and GitHub repository.

Software Requirements
=====================

ReproZip is comprised of two components: **reprozip** (for the packing step) and **reprounzip** (for the unpack step). Additional plugins are also provided for *reprounzip*: **reprounzip-vagrant**, which unpacks the experiment in a Vagrant virtual machine, and **reprounzip-docker**, which unpacks the experiment in a Docker container (please see :ref:`unpackers` for more information).

The operating system compatibility for the two ReproZip components is the following:

+------------------+------------+--------------+--------------+
| Component        | Linux      | Mac OS X     | Windows      |
+==================+============+==============+==============+
| *reprozip*       | Yes        | No           | No           |
+------------------+------------+--------------+--------------+
| *reprounzip*     | Yes        | Yes [#plgn]_ | Yes [#plgn]_ |
+------------------+------------+--------------+--------------+

Python 2.7.3 or greater [#bug]_ is required to run ReproZip. Besides, depending on the component or plugin to be used, some additional software packages are also required, as described below:

+------------------------------+-----------------------------------------+
| Component / Plugin           | Required Software Packages              |
+==============================+=========================================+
| *reprozip*                   | `SQLite <http://www.sqlite.org/>`_,     |
|                              | a working C compiler                    |
+------------------------------+-----------------------------------------+
| *reprounzip*                 | None                                    |
+------------------------------+-----------------------------------------+
| *reprounzip-vagrant*         | `Vagrant <https://www.vagrantup.com/>`_ |
+------------------------------+-----------------------------------------+
| *reprounzip-docker*          | `Docker <https://www.docker.com/>`_     |
+------------------------------+-----------------------------------------+

Obtaining the Software
======================

In ReproZip, each component must be installed separately as they fulfill different purposes. First, install `pip <https://pypi.python.org/pypi/pip>`_ if not yet installed in your environment. Then, to install a ReproZip component, simply run the following command::

    $ pip install <name>

where *<name>* is the name of the component.

The additional plugins for *reprounzip* can also be installed using the same command. Note, however, that *reprounzip* must be installed in the system prior to installing any of the available plugins.

..  rubric:: Footnotes

..  [#plgn] By using either *reprounzip-vagrant* or *reprounzip-docker*.
..  [#bug] This is because of `Python bug 13676 <http://bugs.python.org/issue13676>`_ related to sqlite3.
