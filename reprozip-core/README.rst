ReproZip
========

`ReproZip <https://www.reprozip.org/>`__ is a tool aimed at simplifying the process of creating reproducible experiments from command-line executions, a frequently-used common denominator in computational science. It tracks operating system calls and creates a bundle that contains all the binaries, files and dependencies required to run a given command on the author's computational environment (packing step).  A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

reprozip-core
-------------

This library contains common logic for the various components, such as manipulation of our config file and bundle (``.rpz``) formats.

Please refer to `reprozip <https://pypi.python.org/pypi/reprozip>`__, `reprounzip-vagrant <https://pypi.python.org/pypi/reprounzip-vagrant>`_, and `reprounzip-docker <https://pypi.python.org/pypi/reprounzip-docker>`_ for other components and plugins.

Additional Information
----------------------

For more detailed information, please refer to our `website <https://www.reprozip.org/>`_, as well as to our `documentation <https://docs.reprozip.org/>`_.

ReproZip is currently being developed at `NYU <http://engineering.nyu.edu/>`_. The team includes:

* `Fernando Chirigati <http://fchirigati.com/>`_
* `Juliana Freire <https://vgc.poly.edu/~juliana/>`_
* `Remi Rampin <https://remi.rampin.org/>`_
* `Dennis Shasha <http://cs.nyu.edu/shasha/>`_
* `Vicky Rampin <https://vicky.rampin.org/>`_
