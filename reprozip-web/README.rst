ReproZip
========

`ReproZip <https://www.reprozip.org/>`__ is a tool aimed at simplifying the process of creating reproducible experiments from command-line executions, a frequently-used common denominator in computational science. It tracks operating system calls and creates a bundle that contains all the binaries, files and dependencies required to run a given command on the author's computational environment (packing step).  A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

reprozip-web
----------------

This package provides capture and replay of remote web content, to augment the capture of web applications.

After you have packed your web application into an RPZ file, you can use it to add a web archive to the RPZ with all the content that is used by your application but not served by it, for example stylesheets, images, videos, etc.

You can then use it to replay that RPZ, serving the dynamic content from your application running with reprounzip, and the dynamic content from the bundled web archive.

You can use it from the command-line::

    # Trace & pack like normal
    $ reprozip trace ./start-web-app.sh
    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    ^C
    $ reprozip pack my-web-app.rpz

    # Capture static web content
    $ reprounzip docker setup my-web-app.rpz my-web-app/
    $ reprozip-web capture my-web-app/ --application-host localhost:8000
    $ reprozip-web pack my-web-app.rpz my-web-app/
    $ reprounzip docker destroy my-web-app/

    # Reproduce
    $ reprounzip docker setup my-web-app.rpz my-web-app/
    $ reprozip-web replay my-web-app/

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
