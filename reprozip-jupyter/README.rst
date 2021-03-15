ReproZip
========

`ReproZip <https://www.reprozip.org/>`__ is a tool aimed at simplifying the process of creating reproducible experiments from command-line executions, a frequently-used common denominator in computational science. It tracks operating system calls and creates a bundle that contains all the binaries, files and dependencies required to run a given command on the author's computational environment (packing step).  A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

reprozip-jupyter
----------------

This package provides tracing and reproduction of Jupyter notebooks, allowing one to pack all the libraries and data used in their notebook to allow anyone to re-run it easily.

You can use it from the command-line::

    # Trace & pack
    $ reprozip-jupyter trace mynotebook.ipynb
    $ reprozip pack notebook_environment.rpz

    # Unpack and reproduce
    $ reprounzip docker setup notebook_environment.rpz /tmp/notebook
    $ reprozip-jupyter run /tmp/notebook

Or you can pack directly from the Jupyter notebook interface, if you enable the extension::

    $ jupyter nbextension install --py reprozip_jupyter --user
    $ jupyter nbextension enable --py reprozip_jupyter --user
    $ jupyter serverextension enable --py reprozip_jupyter --user

Please refer to `reprozip <https://pypi.python.org/pypi/reprozip>`__ and `reprounzip <https://pypi.python.org/pypi/reprounzip>`_ for more information.

Additional Information
----------------------

For more detailed information, please refer to our `website <https://www.reprozip.org/>`_, as well as to our `documentation <https://docs.reprozip.org/>`_.

ReproZip is currently being developed at `NYU <http://engineering.nyu.edu/>`_. The team includes:

* `Fernando Chirigati <http://fchirigati.com/>`_
* `Juliana Freire <https://vgc.poly.edu/~juliana/>`_
* `Remi Rampin <https://remi.rampin.org/>`_
* `Dennis Shasha <http://cs.nyu.edu/shasha/>`_
* `Vicky Rampin <https://vicky.rampin.org/>`_
