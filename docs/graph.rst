..  _graph:

reprounzip graph
****************

`reprounzip` comes with the *graph* unpackers. Instead of turning a .rpz pack into an executable directory, it reads the metadata and creates a graph that shows the processes of the original experiment and the files they access.

..  note:: If you are using a Python version older than 2.7.3, this feature will not be available due to `Python bug 13676 <http://bugs.python.org/issue13676>`__ related to sqlite3.

The basic usage is either::

    reprounzip graph graphfile.dot mypackfile.rpz

or, if you just ran `reprozip` and haven't created a pack yet::

    reprounzip graph [-d tracedirectory] graphfile.dot

The default output is a `Graphviz DOT file <http://www.graphviz.org/content/dot-language>`__ that you can turn into an image using for example::

    dot -Tpng graphfile.dot -o graph.png

It is also possible to output a JSON file with ``--json``, which is easier to consume in other programs.

Options
=======

Because most experiments involve a huge number of file accesses, the graph command offers a lot of options to control what will be shown.

Note that all of the following options can be passed multiple times.

Filtering
+++++++++

Files can be filtered out using a regular expression [#re]_ with ``--regex-filter``; for example:

* ``--regex-filter /~[^/]*$``` will filter out files whose name begin with a tilde
* ``--regex-filter ^/usr/share`` will filter out /usr/share recursively
* ``--regex-filter \.bin$`` will filter files with a .bin extension

Mapping
+++++++

You can remap filenames using regular expressions [#re]_ with ``--regex-replace``. This can be useful either:

* to simplify the graph by making filenames shorter, or
* to aggregate multiple files by mapping them to the same name, or
* to fix programs for which the wrong access was logged or which is using some kind of cache, like Python's .pyc files

Example:

* ``--regex-replace .pyc$ \.py`` will replace accesses to bytecode cache files (.pyc) to the original source (.py)
* ``--regex-replace ^/dev(/.*)?$ /dev`` will aggregate all device files as a single path `/dev`
* ``--regex-replace ^/home/vagrant/experiment/data/(.*)\.bin data:\1`` simplifies the paths to some data files

``--aggregate`` is a shortcut allowing to map all files that begin with a prefix to that prefix, for instance ``--aggregate /usr/local`` will collapse all files under ``/usr/local`` as if there was a single path ``/usr/local`` that was used instead of them.

Levels of detail
++++++++++++++++

You can also control how each category of items should be detailed in the output.

For distribution packages:

* ``--packages file`` will show all the files belonging to each package, grouped under that package's name
* ``--packages package`` will show the package as a single item, not detailing the individual files it contains
* ``--packages drop`` will hide the packages entirely, removing all of their files from the output
* ``--packages ignore`` will ignore the packages, treating their files as if they had not been detected as being part of a package

Note that regex filters and replacements are applied before this, so files that are remapped to a package file will show under that package name (for example, .pyc to .py).

For processes:

* ``--processes thread`` will show every process and thread
* ``--processes process`` will show every process but hide threads
* ``--processes run`` will show only one item for a whole run, as if it only used a single process

For the files that are not part of a package (or if ``--packages ignore`` is in use):

* ``--otherfiles all`` will show every file (unless filtered by ``--regex-filter``)
* ``--otherfiles io`` will only show the input and output files, as designated by the configuration
* ``--otherfiles no`` will not show these files at all
