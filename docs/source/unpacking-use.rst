
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

Showing Package Information
+++++++++++++++++++++++++++

Before unpacking an experiment,
it is often useful to have further information
with respect to its package.
The following command allows users to do so::

  $ reprounzip info <package>
  
where <package> corresponds to the experiment package.

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

.. _showfiles:

Showing Input and Output Files
++++++++++++++++++++++++++++++

Coming Soon!

Creating a Provenance Graph
+++++++++++++++++++++++++++

ReproZip also allows users to
generate a *provenance graph* related to
the experiment execution.
This graph
shows the relationships between
files, library dependencies, and
binaries during the execution.
To generate such a graph,
the following command should be used::

  $ reprounzip graph <graph-file> <package>
  
where <graph-file> corresponds to the
graph, outputted using the
`DOT <http://en.wikipedia.org/wiki/DOT_(graph_description_language)>`_ language.


.. _linux_unpacker:

Unpacking an Experiment in Linux
================================

There are three main unpackers specific for
Linux environments: *directory*,
*chroot*, and *installpkgs*.
In the following,
each of these unpackers are explained
in detail.

Running From a Directory
++++++++++++++++++++++++

The *directory* unpacker
(*reprounzip directory*) allows users
to unpack the entire experiment
(including library dependencies)
in a single directory, and to
reproduce the experiment directly
from that directory,
**without interfering with
the current environment**.
It does so by automatically
setting up environment variables
(e.g.: PATH, HOME, and LD_LIBRARY_PATH)
that point the experiment execution
to the created directory.

To create the directory where
the execution takes place,
users should use the command *setup*::

  $ reprounzip directory setup <path> --pack <package>
  
where <path> is the diretory where the experiment
will be unpacked.

After creating the directory, the
experiment can be reproduced by issuing
the *run* command::

  $ reprounzip directory run <path>
  
which will execute the experiment inside
the experiment directory.
Users may also change the command line
of the experiment by using the argument
*--cmdline*::

  $ reprounzip directory run <path> --cmdline <new-command-line>

where <new-command-line> is the modified command line.
This is particularly useful to reproduce
the experiment under different input parameters.

Before reproducing the experiment,
users may also want to change its input files:
users need first to identify the input files
by running the *showfiles* command
(see :ref:`showfiles`),
and then run the *upload* command::

  $ reprounzip directory upload <path> <input-path>:<input-id>
  
where <input-path> is the new input file
and <input-id> is the input file identifier
(from *showfiles*).
Also, after running the experiment,
to copy an output file
from the experiment directory,
users must first run the *showfiles* command
to identify the desired output file, and then run
the *download* command::

  $ reprounzip directory download <path> <output-id>:<output-path>
  
where <output-id> is the output file identifier (from *showfiles*)
and <output-path> is the desired destination of the file.

The experiment directory can be removed by executing
the *destroy* command::

  $ reprounzip directory destroy <path>


Running With *chroot*
+++++++++++++++++++++



Installing Software Packages
++++++++++++++++++++++++++++



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

Further Considerations
======================

Multiple Execution Paths
++++++++++++++++++++++++

Non-Deterministic Experiments
+++++++++++++++++++++++++++++



