
Using *reprounzip*
******************

While *reprozip* is responsible for tracing and packing an experiment,
*reprounzip* is the component used for the unpacking step.
By default, *reprounzip* has three **unpackers** for
Linux (see :ref:`linux_unpacker`),
but plugins may be added to the component so that
experiments can be reproduced in different environments
as well (see :ref:`unpackers`).

Inspecting a Package
====================

Before unpacking an experiment,
it is often useful to have further information
with respect to its package.
The following command allows users to do so::

  $ reprounzip info <package>
  
where *<package>* corresponds to the experiment package.

The output of this command has three sections.
The first section, *Pack Information*, comprises
the main information about the experiment package::

  ----- Pack information -----
  Compressed size: <compressed-size>
  Unpacked size: <unpacked-size>
  Total packed paths: <number-packed-paths>
      Files: <number-files>
      Directories: <number-directories>
      Symbolic links: <number-symlinks>
      
The next section, *Metadata*,
contains information about dependencies
(i.e., software packages),
machine architecture from the packing environment,
and experiment execution::

  ----- Metadata -----
  Total paths: <total-number-dependencies-paths>
  Listed packed paths: <number-packed-dependencies-paths>
  Total software packages: <total-number-software-packages>
  Packed software packages: <number-packed-software-packages>
      Files from packed software packages: <number-files-packed-software-packages>
      Files from unpacked software packages: <number-files-unpacked-software-packages>
  Architecture: <original-architecture> (current: <current-architecture>)
  Distribution: <original-operating-system> (current: <current-operating-system>)
  Executions (1):
      <command-line>
          input files: <number-input-files>
          output files: <number-output-files>
          wd: <original-working-directory>
          exitcode: <original-exit-code>

Note that, for *architecture* and *distribution*,
the command shows information with respect to
both the original environment (i.e.: the environment
where the experiment was packed) and
the current one (i.e.: the environment
where the experiment is to be unpacked).

Last, the section *Unpackers* shows
which of the installed *reprounzip* unpackers
can be successfully used in the current environment
(taking into account its compatibility
with the original one)::

  ----- Unpackers -----
  Compatible:
      ...
  Incompatible:
      ...
  Unknown:
      ...
      
*Compatible* lists the unpackers that can
be used in the current environment,
e.g.: for an experiment originally packed on Ubuntu
and to be reproduced on Windows,
*vagrant* is compatible (see :ref:`vagrant`);
*Incompatible* lists the unpackers
that cannot be used in the current environment,
e.g.: *installpkgs* on Windows (see :ref:`linux_unpacker`);
and *Unknown* lists the installed unpackers
that cannot be executed for reasons different from
operating system incompatibility,
e.g.: plugin for *vagrant* is installed,
but not the Vagrant software.

ReproZip also allows users to
generate a *provenance graph* related to
the experiment execution.
The graph
shows the relationships between
files, library dependencies, and
binaries during the execution.
To generate such a graph,
the following command should be used::

  $ reprounzip graph <graph-file> <package>
  
where *<graph-file>* corresponds to the
graph, outputted using the
`DOT <http://en.wikipedia.org/wiki/DOT_(graph_description_language)>`_ language.


.. _linux_unpacker:

Unpacking an Experiment in Linux
================================



.. _unpackers:

Additional Unpackers
====================

.. _vagrant:

Vagrant Plugin
++++++++++++++



Docker Plugin
+++++++++++++



VisTrails Plugin
++++++++++++++++

Coming soon!