..  _unpacking:

Using *reprounzip*
******************

While *reprozip* is responsible for tracing and packing an experiment, *reprounzip* is the component used for the unpacking step. *reprounzip* is distributed with three **unpackers** for Linux (see :ref:`linux_unpacker`), but more unpackers can be provided through plugins; some of these are compatible with different environment as well (see :ref:`unpackers`).

..  _unpack-info:

Showing Package Information
===========================

Before unpacking an experiment, it is often useful to have further information with respect to its package. **The info command** allows users to do so::

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

**The showfiles command** can be used to list the input and output files defined for that experiment. This is useful if you want to substitute an input file with another of your files, or get an output file out for further examination::

    $ reprounzip showfiles package.rpz
    Input files:
        program_config
        ipython_config
        input_data
    Output files:
        rendered_image
        logfile

See the `input and output files <#unpacker-input-output>`_ section for more information.

Creating a Provenance Graph
===========================

ReproZip also allows users to generate a *provenance graph* related to the experiment execution. This graph shows the relationships between files, library dependencies, and binaries during the execution. To generate such a graph, the following command should be used::

    $ reprounzip graph package.rpz graph-file.dot
    $ dot -Tpng graph-file.dot -o image.png

where `graph-file.dot` corresponds to the graph, outputted in the `DOT <http://en.wikipedia.org/wiki/DOT_(graph_description_language)>`_ language.

Unpacker plugins
================

The main point of splitting ReproZip in a packing and an unpacking step is to allow users to set up the experiment for execution in any of several different ways, from the same ``.rpz`` file that the packer produced. These options for execution are provided by *unpackers*. Thanks to this decoupling, when you install a new unpacker, you can instantly use it on old ``.rpz`` files.

Unpackers are general plugins that can provide their own command-line syntax and options. Because of that, although unpackers usually use the same general commands, you need to explicitely provide the unpacker's name for every command, for instance::

    reprounzip vagrant run myexperiment
    reprounzip vagrant destroy myexperiment

ReproUnzip comes with two unpackers, `directory` and `chroot`, which can be used on Linux only. Others such as `vagrant` and `docker` can be installed separately as plugins; keep reading for a description of the unpackers.

..  _linux_unpacker:

..  _unpack-directory:

`directory` unpacker: unpack as a plain directory
+++++++++++++++++++++++++++++++++++++++++++++++++

This unpacker is distributed with `reprounzip`.

The *directory* unpacker (``reprounzip directory``) allows users to unpack the entire experiment (including library dependencies) in a single directory, and to reproduce the experiment directly from that directory. It does so by automatically setting up environment variables (e.g.: ``PATH``, ``HOME``, and ``LD_LIBRARY_PATH``) that point the experiment execution to the created directory, which has the same structure as in the packing environment.

Note however that, although this unpacker is easy to use and does not require any privilege on the reproducing machine, it is unreliable since the directory is not isolated in any way from the rest of the system; in particular, should the experiment use absolute paths, they will hit the host system instead. This is fine if the system has the required packages (see :ref:`unpack-installpkgs`), and the experiment's own files are addressed with relative paths.

**Limitation:** ``reprounzip directory`` will fail if the binaries involved in the experiment use hardcoded paths, as they will point outside the unpacked directory. The other unpackers are more reliable in that regard.

..  _unpack-chroot:

`chroot` unpacker: isolation with the *chroot* mechanism
++++++++++++++++++++++++++++++++++++++++++++++++++++++++

This unpacker is distributed with `reprounzip`.

In the *chroot* unpacker (``reprounzip chroot``), similar to *reprounzip directory*, a directory is created from the experiment package, but a full system environment is built, which can then be run with ``chroot(2)`` (a Linux mechanism to change the root directory ``/`` for the experiment to the experiment directory). Therefore, this unpacker addresses the limitation of *reprounzip directory* and does not fail in the presence of harcoded paths. It also **does not interfere with the current environment** since the experiment is isolated in that single directory.

**Warning:** do **not** try to delete the experiment directory, **always** use ``reprounzip chroot destroy``. If ``/dev`` is mounted inside, you would also delete your system's device pseudofiles (these can be restored by rebooting or running the ``MAKEDEV`` script).

**Limitation:** although *chroot* offers pretty good isolation, it is not considered completely safe: it is possible for processes owned by root to "escape" to the outer system. Do not run untrusted programs with this plugin either.

..  _unpack-installpkgs:

Installing Software Packages
++++++++++++++++++++++++++++

This unpacker is distributed with `reprounzip`.

By default, ReproZip identifies if the current environment already has the required software packages for the experiment, using the installed ones; for the non-installed software packages, it uses the dependencies packed in the original environment and extracted under the experiment directory.

Users may also let ReproZip try and install all the dependencies of the experiment on their machine by using the *installpkgs* unpacker (``reprounzip installpkgs``). This unpacker currently works for Debian and Debian-based operating systems only (e.g.: Ubuntu), and uses the `dpkg <http://en.wikipedia.org/wiki/Dpkg>`_ package manager to automatically install all the required software packages directly on the current machine, thus **interfering with your environment**.

To install the required dependencies, the following command should be used::

    $ reprounzip installpkgs <package>

Users may use flag *y* or *assume-yes* to automatically confirm all the questions from the package manager; flag *missing* to install only the software packages that were not originally included in the experiment package (i.e.: software packages excluded in the configuration file); and flag *summary* to simply provide a summary of which software packages are installed or not in the current environment **without installing any dependency**.

Note that this unpacker is only used to install software packages. Users still need to use either *reprounzip directory* or *reprounzip chroot* to extract the experiment and execute it.

..  _unpackers:

..  _unpack-vagrant:

`vagrant` unpacker: build a virtual machine
+++++++++++++++++++++++++++++++++++++++++++

This unpacker is NOT distributed with `reprounzip`. It is a separate package `reprounzip-vagrant <https://pypi.python.org/pypi/reprounzip-vagrant/>`_, which you should install before use.

The *reprounzip-vagrant* plugin allows an experiment to be unpacked and reproduced using a virtual machine created through `Vagrant <https://www.vagrantup.com/>`_. Therefore, the experiment can be reproduced in any environment supported by this tool, i.e.: Linux, Mac OS X, and Windows. Note that the plugin assumes that Vagrant is installed in the current environment.

In addition to the commands listed in `Unpacker commands <#unpacker-commands>`_, you can use ``suspend`` to save the virtual machine state to disk, and ``setup/start`` to restart a previously-created machine::

    $ reprounzip vagrant suspend <path>
    $ reprounzip vagrant setup/start <path>

..  _docker-plugin:

`docker` unpacker: build a Docker container
+++++++++++++++++++++++++++++++++++++++++++

This unpacker is NOT distributed with `reprounzip`. It is a separate package `reprounzip-docker <https://pypi.python.org/pypi/reprounzip-docker/>`_, which you should install before use.

ReproZip can also extract and reproduce experiments as `Docker <https://www.docker.com/>`_ containers. The *reprounzip-docker* plugin is the one responsible for such integration and it assumes that Docker is already installed in the current environment.

..  _unpacker-commands:

Using an unpacker
=================

Once you have chosen (and installed) an unpacker for your machine, you can use it to setup, run, and destroy your experiment. An unpacker creates a **experiment directory** in which its working files are put; these can be either the full filesystem (for *directory* or *chroot*) or less simple content (like a handle on a virtual machine). In the case of *chroot*, it might have mount points. To make sure that you don't damage your machine and actually free all resources, you should **always use the destroy command** to delete the experiment directory, not merely delete it.

All the following commands need to state which unpacker is being used. The main commands are available for each unpacker, so to use a different one, just replace ``vagrant`` in the following text with the actual unpacker you are using (for instance, instead of ``reprounzip vagrant setup eclipse.rpz eclipse_dir``, run ``reprounzip docker setup eclipse.rpz elipse_dir``).

Setting up an experiment directory
++++++++++++++++++++++++++++++++++

To create the directory where the execution will take place, users should use the command *setup*::

    $ reprounzip vagrant setup <package> <path>

where `<path>` is the directory where the experiment will be unpacked.

Note that once this is done, you should only delete `<path>` with the `destroy` command described below; deletion might leave files behind, or even damage your system through bound filesystems.

The following commands take the `<path>` argument; they don't need the original package to run.

Running the experiment
++++++++++++++++++++++

After creating the directory, the experiment can be reproduced by issuing the *run* command::

    $ reprounzip vagrant run <path>

which will execute the entire experiment inside the experiment directory. Users may also change the command line of the experiment by using the argument *cmdline*::

    $ reprounzip vagrant run <path> --cmdline <new-command-line>

where `<new-command-line>` is the modified command line. This is particularly useful to reproduce and test the experiment under different input parameter values. Using ``--cmdline`` without an argument prints the initial command line, so you can make your changes.

Destroying the experiment directory
+++++++++++++++++++++++++++++++++++

This command will unmount mounted paths, destroy virtual machines, free container images, ... and delete the experiment directory for you. Make sure you use it instead of simply deleting, to avoid surprises; unpackers can do very funny stuff::

    $ reprounzip vagrant destroy <path>

..  _unpacker-input-output:

Using input and output files
++++++++++++++++++++++++++++

When tracing, ReproZip tries to identify which are the input and output files of the experiment. This can also be adjusted in the configuration file before packing.

If the experiment you unpacked has such files, you can use the following commands to manipulate them.

Input or output files are identified by a name, which is either choosen by ReproZip or set in the configuration file by the author of the ``.rpz`` file. Before you do anything, you can list these files using the `showfiles` command::

    $ reprounzip showfiles <path>
    Input files:
        program_config
        ipython_config
        input_data
    Output files:
        rendered_image
        logfile

Adding ``-v`` will also show the path of said file in the experiment environment.

If you choose to substitute an input file, reprounzip will simply overwrite that path in the environment with the file you provide from your system. Simply use the `upload` command::

    $ reprounzip vagrant upload <path> <input-path>:<input-id>

where `<input-path>` is the new file's path and `<input-id>` is the input file to replace (from `showfiles`). To restore the original input file, the same command, but in the following format::

    $ reprounzip directory upload <path> :<input-id>

After running the experiment, all the generated output files will be located under the experiment directory. To copy an output file from this directory to another desired location, users may first list these files by running `showfiles`, and then run the `download` command::

    $ reprounzip directory download <path> <output-id>:<output-path>

where `<output-id>` is the output file to get (from `showfiles`) and `<output-path>` is the desired destination of the file. If no destination is specified, the file will be printed to stdout::

    $ reprounzip directory download <path> <output-id>:

Note that upload puts the id on the right, and download puts it on the left. The meaning is that the thing on the left of the colon is moved to the right; for upload this is path-to-id, for download, id-to-path.

Running the `showfiles` command on the experiment directory will show you what the input files are currently set to::

    $ reprounzip showfiles <path>
    Input files:
        program_config
            (original)
        ipython_config
            C:\Users\Remi\Documents\ipython-config
    ...

In this example, the input named `program_config` hasn't been touched, so the one bundled in the ``.rpz`` file will be used, while the input named `ipython_config` as been replaced.

Further Considerations
======================

Reproducing Multiple Execution Paths
++++++++++++++++++++++++++++++++++++

The *reprozip* component can only guarantee that *reprounzip* will successfully reproduce the same execution path that the original experiment followed. There is no guarantee that the experiment won't need a different set of files if you use a different configuration; if some of these files were not packed into the ``.rpz`` package, the reproduction may fail.
