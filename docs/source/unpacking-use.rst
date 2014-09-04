
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
the main information about the experiment package,
including size and total number of files::

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
  Executions:
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
This helps users understand
the differences between the environments
in order to provide a better guidance in
choosing the most appropriate unpacker.

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
in a single directory,
and to reproduce the experiment directly
from that directory,
**without interfering with
the current environment**.
It does so by automatically
setting up environment variables
(e.g.: PATH, HOME, and LD_LIBRARY_PATH)
that point the experiment execution
to the created directory, which has
the same structure
as in the packing environment.

To create the directory where
the execution will take place,
users should use the command *setup*::

  $ reprounzip directory setup <path> --pack <package>
  
where <path> is the diretory where the experiment
will be unpacked.

After creating the directory, the
experiment can be reproduced by issuing
the *run* command::

  $ reprounzip directory run <path>
  
which will execute the entire experiment inside
the experiment directory.
Users may also change the command line
of the experiment by using the argument
*cmdline*::

  $ reprounzip directory run <path> --cmdline <new-command-line>

where <new-command-line> is the modified command line.
This is particularly useful to reproduce and test
the experiment under different input parameter values.

Before reproducing the experiment,
users also have the option to change the input files.
First, users need to identify the identifiers for these files
by running the *showfiles* command
(see :ref:`showfiles`),
and then run the *upload* command::

  $ reprounzip directory upload <path> <input-path>:<input-id>
  
where <input-path> is the new input file path
and <input-id> is the input file identifier
(from *showfiles*).
This command essentially replaces the file identified
by <input-id> with the user file under <input-path>.

After running the experiment,
all the generated output files
will be located under the experiment directory.
To copy an output file
from this directory
to another desired location,
users must first run the *showfiles* command
to identify the identifier of this file, and then run
the *download* command::

  $ reprounzip directory download <path> <output-id>:<output-path>
  
where <output-id> is the output file identifier (from *showfiles*)
and <output-path> is the desired destination of the file.

The experiment directory can be removed by using
the *destroy* command::

  $ reprounzip directory destroy <path>

**Limitation:** *reprounzip directory*
will fail if the binaries involved in the experiment
use hardcoded paths, as ReproZip cannot
modify them.

Running With *chroot*
+++++++++++++++++++++

In the *chroot* unpacker (*reprounzip chroot*),
similar to *reprounzip directory*,
a directory is created from the experiment package,
but a chroot environment is also built under this
directory.
This fundamentally changes the root directory of the
current environment to the experiment directory,
creating a virtualized copy of the original environment.
Therefore, this unpacker addresses
the limitation of *reprounzip directory*
and does not fail in the presence of harcoded paths.
Note that this unpacker **does not interfere
with the current environment** either.

To create the directory of the
chroot environment,
users should use the command *setup/create*::

  $ reprounzip chroot setup/create <path> --pack <package>
  
where <path> is the diretory where the experiment
will be unpacked for the chroot environment.
If users run this command as root,
ReproZip will restore the owner/group of the
experiment files by default.
To disable this, flag *no-preserve-owner*
can be used::

  $ reprounzip chroot setup/create <path> --pack <package> --no-preserve-owner
  
Next, users need to use the *setup/mount* command
to create the chroot environment under the experiment directory::

  $ reprounzip chroot setup/mount <path>

This command binds */dev* and */proc* inside the experiment directory,
thus creating the chroot environment.
Both the creation and mounting steps (*setup/create* and *setup/mount*, respectively)
can be executed in one step by using
the *setup* command::

  $ reprounzip chroot setup <path> --pack <package>

The commands to replace input files, reproduce the experiment,
and copy output files are the same as for *reprounzip directory*::

  $ reprounzip chroot upload <path> <input-path>:<input-id>
  $ reprounzip chroot run <path> --cmdline <new-command-line>
  $ reprounzip chroot download <path> <output-id>:<output-path>

To remove the chroot environment, users can execute the command *destroy*::

  $ reprounzip directory destroy <path>
  
which unmounts *\dev* and *\proc* from the experiment
directory and then removes the directory.
These steps can also be executed separately by
using the commands *destroy/unmount* and
*destroy/dir*::

  $ reprounzip directory destroy/unmount <path>
  $ reprounzip directory destroy/dir <path>
  
**Warning:** note that, after creating the chroot environment,
the root directory is changed to the experiment directory;
therefore, do **not** use command *rm -Rf* inside this
directory.

Installing Software Packages
++++++++++++++++++++++++++++

By default, ReproZip identifies
if the current environment already has
the required software packages for the experiment,
using the installed ones;
for the non-installed software packages,
it uses the dependencies packed in the original
environment and extracted under the
experiment directory.

Users may also let ReproZip to try installing
all the dependencies of the experiment in
their environment by using the *installpkgs*
unpacker (*reprounzip installpkgs*).
This unpacker currently works for Debian and Dabian-based
operating systems only, and uses the `dpkg <http://en.wikipedia.org/wiki/Dpkg>`_
package manager to automatically install all the
required software packages direclty on
the current environment,
thus **interfering with this environment**.

To install the required dependencies, the following command
should be used::

  $ reprounzip installpkgs <package>
  
Users may use flag *y* or *assume-yes* to automatically confirm
all the questions from the package manager;
flag *missing* to install only the software packages that were not
originally included in the experiment package (i.e.:
software packages excluded in the configuration file);
and flag *summary* to simply provide a summary
of which software packages are installed or not
in the current environment **without installing any dependency**.

Note that this unpacker is only used to install software packages.
Users still need to use either *reprounzip directory* or *reprounzip chroot*
to extract the experiment and execute it.

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



