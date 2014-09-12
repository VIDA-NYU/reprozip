..  _unpacking:

Using *reprounzip*
******************

While *reprozip* is responsible for tracing and packing an experiment, *reprounzip* is the component used for the unpacking step. *reprounzip* is distributed with three **unpackers** for Linux (see :ref:`linux_unpacker`), but more unpackers can be provided through plugins; some of these are compatible with different environment as well (see :ref:`unpackers`).

Inspecting a Package
====================

Showing Package Information
+++++++++++++++++++++++++++

Before unpacking an experiment, it is often useful to have further information with respect to its package. The following command allows users to do so::

    $ reprounzip info <package>

where `<package>` corresponds to the experiment package (i.e.: the ``.rpz`` file). You can pass ``-v`` (for `verbose`) or ``-v -v`` to get more detailed information on the package.

The output of this command has three sections. The first section, `Pack Information`, contains general information about the experiment package, including size and total number of files::

    ----- Pack information -----
    Compressed size: <compressed-size>
    Unpacked size: <unpacked-size>
    Total packed paths: <number>

The next section, `Metadata`, contains information about dependencies (i.e., software packages), machine architecture from the packing environment, and experiment execution::

    ----- Metadata -----
    Total software packages: <total-number-software-packages>
    Packed software packages: <number-packed-software-packages>
    Architecture: <original-architecture> (current: <current-architecture>)
    Distribution: <original-operating-system> (current: <current-operating-system>)
    Executions:
        <command-line>
            wd: <working-directory>
            exitcode: 0

Note that, for `architecture` and `distribution`, the command shows information with respect to both the original environment (i.e.: the environment where the experiment was packed) and the current one (i.e.: the environment where the experiment is to be unpacked). This helps users understand the differences between the environments in order to provide a better guidance in choosing the most appropriate unpacker.

Last, the section `Unpackers` shows which of the installed *reprounzip* unpackers can be successfully used in the current environment::

    ----- Unpackers -----
    Compatible:
        ...
    Incompatible:
        ...

`Compatible` lists the unpackers that can be used in the current environment; `Incompatible` lists the unpackers that cannot be used in the current environment. An additional `Unknown` list shows the installed unpackers that might not work, for example the *vagrant* unpacker if the `vagrant` command is not found in PATH.

For example, for an experiment originally packed on Ubuntu and a user reproducing on Windows, *vagrant* is compatible (see :ref:`unpack-vagrant`), but *installpkgs* is incompatible (we can't use Linux software packages natively).

..  _showfiles:

Showing Input and Output Files
++++++++++++++++++++++++++++++

The `showfiles` command can be used to list the input and output files defined for that experiment. This is useful if you want to substitute an input file with another of your files, or get an output file out for further examination::

    $ reprounzip showfiles package.rpz
    Input files:
        program_config
        ipython_config
        input_data
    Output files:
        rendered_image
        logfile

Creating a Provenance Graph
+++++++++++++++++++++++++++

ReproZip also allows users to generate a *provenance graph* related to the experiment execution. This graph shows the relationships between files, library dependencies, and binaries during the execution. To generate such a graph, the following command should be used::

    $ reprounzip graph package.rpz graph-file.dot
    $ dot -Tpng graph-file.dot -o image.png

where `graph-file.dot` corresponds to the graph, outputted in the `DOT <http://en.wikipedia.org/wiki/DOT_(graph_description_language)>`_ language.

..  _linux_unpacker:

Unpacking an Experiment in Linux
================================

There are three main unpackers specific to Linux environments: :ref:`directory <unpack-directory>`, :ref:`chroot <unpack-chroot>`, and :ref:`installpkgs <unpack-installpkgs>`. In the following, each of these unpackers are explained in detail.

..  _unpack-directory:

Running From a Directory
++++++++++++++++++++++++

The *directory* unpacker (``reprounzip directory``) allows users to unpack the entire experiment (including library dependencies) in a single directory, and to reproduce the experiment directly from that directory. It does so by automatically setting up environment variables (e.g.: ``PATH``, ``HOME``, and ``LD_LIBRARY_PATH``) that point the experiment execution to the created directory, which has the same structure as in the packing environment.

Note however that, although this unpacker is easy to use and does not require any privilege on the reproducing machine, it is unreliable since the directory is not isolated in any way from the rest of the system; in particular, should the experiment use absolute paths, they will hit the host system instead. This is fine if the system has the required packages (see :ref:`unpack-installpkgs`), and the experiment's own files are addressed with relative paths.

To create the directory where the execution will take place, users should use the command *setup*::

    $ reprounzip directory setup <package> <path>

where `<path>` is the diretory where the experiment will be unpacked.

After creating the directory, the experiment can be reproduced by issuing the *run* command::

    $ reprounzip directory run <path>

which will execute the entire experiment inside the experiment directory. Users may also change the command line of the experiment by using the argument *cmdline*::

    $ reprounzip directory run <path> --cmdline <new-command-line>

where `<new-command-line>` is the modified command line. This is particularly useful to reproduce and test the experiment under different input parameter values.

Before reproducing the experiment, users also have the option to change the input files. The input files of the experiment can be listed by running the `showfiles` command (see :ref:`showfiles`), and then run the `upload` command::

    $ reprounzip directory upload <path> <input-path>:<input-id>

where `<input-path>` is the new file's path and `<input-id>` is the input file to replace (from `showfiles`). To restore the original input file, the same command, but in the following format::

    $ reprounzip directory upload <path> :<input-id>

After running the experiment, all the generated output files will be located under the experiment directory. To copy an output file from this directory to another desired location, users may first list these files by running `showfiles`, and then run the `download` command::

    $ reprounzip directory download <path> <output-id>:<output-path>

where `<output-id>` is the output file to get (from `showfiles`) and `<output-path>` is the desired destination of the file. If no destination is specified, the file will be printed to stdout::

    $ reprounzip directory download <path> <output-id>:

The experiment directory can be removed by using the `destroy` command::

    $ reprounzip directory destroy <path>

**Limitation:** ``reprounzip directory`` will fail if the binaries involved in the experiment use hardcoded paths, as they will point outside the unpacked directory. The other unpackers are more reliable in that regard.

..  _unpack-chroot:

Running With *chroot*
+++++++++++++++++++++

In the *chroot* unpacker (``reprounzip chroot``), similar to *reprounzip directory*, a directory is created from the experiment package, but a full system environment is built, which can then be run with ``chroot(2)`` (a Linux mechanism to change the root directory ``/`` for the experiment to the experiment directory). Therefore, this unpacker addresses the limitation of *reprounzip directory* and does not fail in the presence of harcoded paths. It also **does not interfere with the current environment** since the experiment is isolated in that single directory.

To create the directory of the chroot environment, users should use the command `setup`::

    $ reprounzip chroot setup <package> <path>

where `<path>` is the diretory where the experiment will be unpacked for the chroot environment. If users run this command as root, ReproZip will restore the owner/group of the experiment files by default (unless `--no-preserve-owner` is used), and will mount your ``/dev`` and ``/proc`` directory inside the chroot (unless ``--dont-mount-magic-dirs`` is used).

The commands to replace input files, reproduce the experiment, and copy output files are the same as for ``reprounzip directory``::

    $ reprounzip chroot upload <path> <input-path>:<input-id>
    $ reprounzip chroot run <path> --cmdline <new-command-line>
    $ reprounzip chroot download <path> <output-id>:<output-path>

To remove the chroot environment, users can execute the command `destroy`::

    $ reprounzip chroot destroy <path>

which unmounts ``/dev`` and ``/proc`` from the experiment directory and then removes the directory.

**Warning:** do **not** try to delete the experiment directory, **always** use ``reprounzip chroot destroy``. If ``/dev`` is mounted inside, you would also delete your system's device pseudofiles (these can be restored by rebooting or running the ``MAKEDEV`` script).

..  _unpack-installpkgs:

Installing Software Packages
++++++++++++++++++++++++++++

By default, ReproZip identifies if the current environment already has the required software packages for the experiment, using the installed ones; for the non-installed software packages, it uses the dependencies packed in the original environment and extracted under the experiment directory.

Users may also let ReproZip to try installing all the dependencies of the experiment in their environment by using the *installpkgs* unpacker (``reprounzip installpkgs``). This unpacker currently works for Debian and Debian-based operating systems only (e.g.: Ubuntu), and uses the `dpkg <http://en.wikipedia.org/wiki/Dpkg>`_ package manager to automatically install all the required software packages directly on the current machine, thus **interfering with this environment**.

To install the required dependencies, the following command should be used::

    $ reprounzip installpkgs <package>

Users may use flag *y* or *assume-yes* to automatically confirm all the questions from the package manager; flag *missing* to install only the software packages that were not originally included in the experiment package (i.e.: software packages excluded in the configuration file); and flag *summary* to simply provide a summary of which software packages are installed or not in the current environment **without installing any dependency**.

Note that this unpacker is only used to install software packages. Users still need to use either *reprounzip directory* or *reprounzip chroot* to extract the experiment and execute it.

..  _unpackers:

Additional Unpackers
====================

ReproZip has some plugins for the *reprounzip* component that provide a new range of unpackers for the system, even allowing a Linux experiment to be reproduced in different environments (e.g.: Mac OS X and Windows). These plugins do not come builtin with *reprounzip* and need to be installed separately, **after** installing *reprounzip*.

..  _unpack-vagrant:

Vagrant Plugin
++++++++++++++

The *reprounzip-vagrant* plugin allows an experiment to be unpacked and reproduced using a virtual machine created through `Vagrant <https://www.vagrantup.com/>`_. Therefore, the experiment can be reproduced in any environment supported by this tool, i.e.: Linux, Mac OS X, and Windows. Note that the plugin assumes that Vagrant is installed in the current environment.

To create the virtual machine for an experiment package, the `setup` command should be used::

    $ reprounzip vagrant setup <package> <path>

where `<path>` is the destination directory for the Vagrant virtual machine.

The commands to replace input files, reproduce the experiment, and copy output files are the same as other unpackers::

    $ reprounzip vagrant upload <path> <input-path>:<input-id>
    $ reprounzip vagrant run <path> --cmdline <new-command-line>
    $ reprounzip vagrant download <path> <output-id>:<output-path>

Users can also suspend the virtual machine (without destroying it) by using the `suspend` command::

    $ reprounzip vagrant suspend <path>

After suspended, the virtual machine can be resumed by using the `setup/start` command.

To destroy the virtual machine, the following command must be used::

    $ reprounzip vagrant destroy <path>

..  _docker-plugin:

Docker Plugin
+++++++++++++

ReproZip can also extract and reproduce experiments using `Docker <https://www.docker.com/>`_ containers. The *reprounzip-docker* plugin is the one responsible for such integration and it assumes that Docker is already installed in the current environment.

To create the container for an experiment package, the following command should be used::

    $ reprounzip docker setup <package> <path>

where <path> is the destination directory for the Docker files.

The commands to replace input files, reproduce the experiment, and copy output files are the same as in previous unpackers::

    $ reprounzip docker upload <path> <input-path>:<input-id>
    $ reprounzip docker run <path> --cmdline <new-command-line>
    $ reprounzip docker download <path> <output-id>:<output-path>

To destroy the container, the following command must be used::

    $ reprounzip docker destroy <path>

Further Considerations
======================

Reproducing Multiple Execution Paths
++++++++++++++++++++++++++++++++++++

The *reprozip* component can only guarantee that *reprounzip* will successfully reproduce the same execution path that the original experiment followed. There is no guarantee that the experiment won't need a different set of files if you use a different configuration; if some of these files were not packed into the ``.rpz`` package, the reproduction may fail.
