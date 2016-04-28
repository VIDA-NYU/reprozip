ReproZip
========

`ReproZip <http://vida-nyu.github.io/reprozip/>`__ is a tool aimed at simplifying the process of creating reproducible
experiments from command-line executions, a frequently-used common denominator
in computational science. It tracks operating system calls and creates a package
that contains all the binaries, files and dependencies required to run a given
command on the author's computational environment (packing step).
A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

reprounzip-docker
-----------------

This is the component responsible for the unpacking step
on different environments (Linux, Windows, and Mac OS X)
by using a `Docker <https://www.docker.com/>`_ container.

Please refer to `reprozip <https://pypi.python.org/pypi/reprozip>`__,
`reprounzip <https://pypi.python.org/pypi/reprounzip>`_,
and `reprounzip-vagrant <https://pypi.python.org/pypi/reprounzip-vagrant>`_
for other components and plugins.


Additional Information
----------------------

For more detailed information, please refer to our `website <http://vida-nyu.github.io/reprozip/>`_, as well as to
our `documentation <http://reprozip.readthedocs.io/>`_.

ReproZip is currently being developed at `NYU <http://engineering.nyu.edu/>`_. The team includes:

* `Fernando Chirigati <http://vgc.poly.edu/~fchirigati/>`_
* `Remi Rampin <http://remram.fr/>`_
* `Dennis Shasha <http://cs.nyu.edu/shasha/>`_
* `Juliana Freire <http://vgc.poly.edu/~juliana/>`_
