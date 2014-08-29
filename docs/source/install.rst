
Installation
************

ReproZip is available as open source, released under the Revised BSD License. Please visit `ReproZip's website <http://vida-nyu.github.io/reprozip/>`_ to find links to our PyPI packages and GitHub repository.

Software Requirements
=====================

ReproZip is comprised of two components: **reprozip** (for the packing step) and **reprounzip** (for the unpack step). Additional plugins are also provided for *reprounzip*: **reprounzip-vagrant**, which unpacks the experiment in a Vagrant [2]_ virtual machine, and **reprounzip-docker**, which unpacks the experiment in a Docker [3]_ container (please see :doc:`unpackers` for more information).

The operating system compatibility for the two ReproZip components is the following:

+------------------+------------+--------------+------------+
| Component        | Linux      | Mac OS X     | Windows    |
+==================+============+==============+============+
| *reprozip*       | Yes        | No           | No         |
+------------------+------------+--------------+------------+
| *reprounzip*     | Yes        | Yes [1]_     | Yes [1]_   |
+------------------+------------+--------------+------------+

Python 2.7.3 or greater is required to run ReproZip.
Besides, depending on the component or plugin to be used, some additional software packages are also required,
as described below:

+------------------------------+-----------------------------------------------+
| Component / Plugin           | Required Software Packages                    |
+==============================+===============================================+
| *reprozip*                   | SQLite [4]_, libconfig-yaml-perl [5]_         |
+------------------------------+-----------------------------------------------+
| *reprounzip*                 | None                                          |
+------------------------------+-----------------------------------------------+
| *reprounzip-vagrant*         | Vagrant [2]_                                  |
+------------------------------+-----------------------------------------------+
| *reprounzip-docker*          | Docker [3]_                                   |
+------------------------------+-----------------------------------------------+


Obtaining the Software
======================

In ReproZip, each component must be installed separately as they fulfill different purposes.
First, install `pip <https://pypi.python.org/pypi/pip>`_ if not yet installed in your environment.
Then, to install a ReproZip component, simply run the following command::

  $ pip install <name>
  
where *<name>* is the name of the component.

The additional plugins for *reprounzip* can also be installed using the same command.
Note, however, that *reprounzip* must be installed in the system prior to installing
any of the available plugins.

.. rubric:: Footnotes

.. [1] By using either *reprounzip-vagrant* or *reprounzip-docker*.
.. [2] Vagrant: https://www.vagrantup.com/
.. [3] Docker: https://www.docker.com/
.. [4] SQLite: http://www.sqlite.org/
.. [5] libconfig-yaml-perl: https://packages.debian.org/sid/libconfig-yaml-perl