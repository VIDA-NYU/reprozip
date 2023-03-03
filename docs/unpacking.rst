..  _unpacking:

Using *reprounzip*
******************

While *reprozip* is responsible for tracing and packing an experiment, *reprounzip* is the component used for the unpacking step. *reprounzip* is distributed with three **unpackers** for Linux (:ref:`reprounzip directory <unpack-directory>`, :ref:`reprounzip chroot <unpack-chroot>`, and :ref:`reprounzip installpkgs <unpack-installpkgs>`), but more unpackers are supported by installing additional plugins; some of these plugins are compatible with different environments as well (e.g.: :ref:`reprounzip-vagrant <unpack-vagrant>` and :ref:`reprounzip-docker <docker-plugin>`).

..  _unpack-info:

Inspecting a Bundle
===================

Showing Bundle Information
++++++++++++++++++++++++++

Before unpacking an experiment, it is often useful to have further information with respect to its bundle. The ``reprounzip info`` command allows users to do so::

    $ reprounzip info <bundle>

where `<bundle>` corresponds to the experiment bundle (i.e., the ``.rpz`` file).

The output of this command has three sections. The first section, `Pack information`, contains general information about the experiment bundle, including size and total number of files::

    ----- Pack information -----
    Compressed size: <compressed-size>
    Unpacked size: <unpacked-size>
    Total packed paths: <number>

The next section, `Metadata`, contains information about dependencies (i.e., software packages), machine architecture from the packing environment, and experiment runs::

    ----- Metadata -----
    Total software packages: <total-number-software-packages>
    Packed software packages: <number-packed-software-packages>
    Architecture: <original-architecture> (current: <current-architecture>)
    Distribution: <original-operating-system> (current: <current-operating-system>)
    Runs:
        <run-id>: <command-line>
        <run-id>: <command-line>
        ...

Note that, for `Architecture` and `Distribution`, the command shows information with respect to both the original environment (i.e., the environment where the experiment was packed) and the current one (i.e., the environment where the experiment is to be unpacked). This helps users understand the differences between the environments in order to provide a better guidance in choosing the most appropriate unpacker.

If the verbose mode is used, more detailed information on the runs is provided::

    $ reprounzip -v info <bundle>
    ...
    ----- Metadata -----
    ...
    Runs:
        <run-id>: <command-line>
            wd: <working-directory>
            exitcode: <exit-code>
        <run-id>: <command-line>
            wd: <working-directory>
            exitcode: <exit-code>
        ...

Last, the section `Unpackers` shows which of the installed *reprounzip* unpackers can be successfully used in the current environment::

    ----- Unpackers -----
    Compatible:
        ...
    Incompatible:
        ...
    Unknown:
        ...

`Compatible` lists the unpackers that can be used in the current environment, while `Incompatible` lists the unpackers that are not supported in the current environment. When using the verbose mode, an additional `Unknown` list shows the installed unpackers that may not work. As an example, for an experiment originally packed on Ubuntu and a user reproducing it on Windows, the `vagrant` unpacker (available through the :ref:`reprounzip-vagrant <unpack-vagrant>` plugin) is compatible, but :ref:`installpkgs <unpack-installpkgs>` is not; `vagrant` may also be listed under `Unknown` if ``vagrant`` is not in PATH (e.g.: if `Vagrant <https://www.vagrantup.com/>`__ is not installed).

..  _showfiles:

Showing Input and Output Files
++++++++++++++++++++++++++++++

The ``reprounzip showfiles`` command can be used to list the input and output files defined for the experiment. These files are identified by an id, which is either chosen by ReproZip or set in the configuration file before creating the ``.rpz`` file::

    $ reprounzip showfiles bundle.rpz
    Input files:
        program_config
        ipython_config
        input_data
    Output files:
        rendered_image
        logfile

Using the flag ``-v`` shows the complete path of each of these files in the experiment environment::

    $ reprounzip -v showfiles bundle.rpz
    Input files:
        program_config (/home/user/.progrc)
        ipython_config (/home/user/.ipython/profile_default/ipython_config.py)
        input_data (/home/user/experiment/input.bin)
    Output files:
        rendered_image (/home/user/experiment/output.png)
        logfile (/home/user/experiment/log.txt)

You can use the ``--input`` or ``--output`` flags to show only files that are inputs or outputs. If the bundle contains multiple runs, you can also filter files for a specific run::

    $ reprounzip -v showfiles bundle.rpz preprocessing-step
    Input files:
        input_data (/home/user/experiment/input.bin)
    Output files:
        logfile (/home/user/experiment/log.txt)

where `preprocessing-step` is the run id. To see the dataflow of the experiment, please refer to :ref:`graph`.

The ``reprounzip showfiles`` command is particularly useful if you want to replace an input file with your own, or to get and save an output file for further examination. Please refer to :ref:`unpacker-input-output` for more information.

..  versionadded:: 1.0.4
    The ``--input`` and ``--output`` flags.

..  _provenance-graph:

Creating a Provenance Graph
+++++++++++++++++++++++++++

ReproZip also allows users to generate a *provenance graph* related to the experiment execution by reading the metadata available in the ``.rpz`` bundle. This graph shows the experiment runs as well as the files and other dependencies they access during execution; this is particularly useful to visualize and understand the dataflow of the experiment.

See :ref:`graph` for details.

..  _unpack-unpackers:

Unpackers
=========

From the same ``.rpz`` bundle, `reprounzip` allows users to set up the experiment for reproduction in several ways by the use of different `unpackers`. Unpackers are plugins that have general interface and commands, but can also provide their own command-line syntax and options. Thanks to the decoupling between packing and unpacking steps, ``.rpz`` files from older versions of ReproZip can be used with new unpackers.

The `reprounzip` tool comes with three unpackers that are only compatible with Linux (``reprounzip directory``, ``reprounzip chroot``, and ``reprounzip installpkgs``). Additional unpackers, such as ``reprounzip vagrant`` and ``reprounzip docker``, can be installed separately. Next, each unpacker is described in more details; for more information on how to use an unpacker, please refer to :ref:`unpacker-commands`.

..  _unpack-directory:

The `directory` Unpacker: Unpacking as a Plain Directory
++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The *directory* unpacker (``reprounzip directory``) allows users to unpack the entire experiment (including library dependencies) in a single directory, and to reproduce the experiment directly from that directory. It does so by automatically setting up environment variables (e.g.: PATH, HOME, and LD_LIBRARY_PATH) that point the experiment execution to the created directory, which has the same structure as in the packing environment.

Please note that, although this unpacker is easy to use and does not require any privilege on the reproducing machine, it is **unreliable** since the directory is not isolated in any way from the remainder of the system. In particular, should the experiment use absolute paths, they will hit the host system instead. However, if the system has all the required packages (see :ref:`unpack-installpkgs`), and the experiment's files are addressed with relative paths, the use of this unpacker should not cause any problems.

..  warning:: ``reprounzip directory`` provides no isolation of the filesystem, as mentioned before. If the experiment uses absolute paths, either provided by you or hardcoded in the experiment, **they will point outside the unpacked directory**.  Please be careful to use relative paths in the configuration and command line if you want this unpacker to work with your experiment. Other unpackers are more reliable in this regard.

..  note:: ``reprounzip directory`` is automatically distributed with `reprounzip`.

..  seealso:: :ref:`Why does 'reprounzip directory' fail with "IOError"? <directory_error>`

..  _unpack-chroot:

The `chroot` Unpacker: Providing Isolation with the *chroot* Mechanism
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

In the *chroot* unpacker (``reprounzip chroot``), similar to ``reprounzip directory``, a directory is created from the experiment bundle; however, a full system environment is also built, which can then be run with ``chroot(2)``, a Linux mechanism that changes the root directory ``/`` for the experiment to the experiment directory. Therefore, this unpacker addresses the limitation of the *directory* unpacker and does not fail in the presence of hardcoded absolute paths. Note as well that it **does not interfere with the current environment** since the experiment is isolated in that single directory.

..  warning:: Do **not** try to delete the experiment directory manually; **always** use ``reprounzip chroot destroy``. If ``/dev`` is mounted inside, you will also delete your system's device pseudo-files (these can be restored by rebooting or running the ``MAKEDEV`` script).

..  note:: Although *chroot* offers pretty good isolation, it is not considered completely safe: it is possible for processes owned by root to "escape" to the outer system. We recommend not running untrusted programs with this plugin.

..  note:: ``reprounzip chroot`` is automatically distributed with `reprounzip`.

..  _unpack-installpkgs:

The `installpkgs` Unpacker: Installing Software Packages
++++++++++++++++++++++++++++++++++++++++++++++++++++++++

By default, ReproZip identifies if the current environment already has the required software packages for the experiment, then using the installed ones for reproduction. For the non-installed software packages, it uses the dependencies packed in the original environment and extracted under the experiment directory.

Users may also let ReproZip try and install all the dependencies of the experiment on their machine by using the *installpkgs* unpacker (``reprounzip installpkgs``). This unpacker currently works for distribution based on Debian or RPM packages (e.g.: Ubuntu, CentOS, Fedora, ...), and uses the package manager to automatically install all the required software packages directly on the current machine, thus **interfering with your environment**.

To install the required dependencies, the following command should be used::

    $ reprounzip installpkgs <bundle>

Users may use flag *y* or *assume-yes* to automatically confirm all the questions from the package manager; flag *missing* to install only the software packages that were not originally included in the experiment package (i.e.: software packages excluded in the configuration file); and flag *summary* to simply provide a summary of which software packages are installed or not in the current environment **without installing any dependency**.

..  warning:: Note that the package manager may not install the same software version as required for running the experiment, and if the versions are incompatible, the reproduction may fail.

..  note:: This unpacker is only used to install software packages. Users still need to use either ``reprounzip directory`` or ``reprounzip chroot`` to extract the experiment and execute it.

..  note:: ``reprounzip installpkgs`` is automatically distributed with `reprounzip`.

..  _unpackers:

..  _unpack-vagrant:

The `vagrant` Unpacker: Building a Virtual Machine
++++++++++++++++++++++++++++++++++++++++++++++++++

The *vagrant* unpacker (``reprounzip vagrant``) allows an experiment to be unpacked into a Virtual Machine and reproduced in that emulated environment, by automatically using `Vagrant <https://www.vagrantup.com/>`__. Therefore, the experiment can be reproduced in any environment supported by this tool, i.e., Linux, Mac OS X, and Windows. Note that the plugin assumes that Vagrant and VirtualBox are installed on your machine.

In addition to the commands listed in :ref:`unpacker-commands`, you can use ``suspend`` to save the virtual machine state to disk, and ``setup/start`` to restart a previously-created machine::

    $ reprounzip vagrant suspend <path>
    $ reprounzip vagrant setup/start <path>

The ``setup`` command also takes a ``--memory`` argument to explicitely select how many megabytes of RAM to allocate to the virtual machine.

..  note:: This unpacker is **not** distributed with `reprounzip`; it is a separate package that should be installed before use (see :ref:`install`).

..  versionadded:: 1.0.1
    The ``--memory`` option.

..  versionadded:: 1.0.4
    The ``suspend`` command.

..  _docker-plugin:

The `docker` Unpacker: Building a Docker Container
++++++++++++++++++++++++++++++++++++++++++++++++++

ReproZip can also extract and reproduce experiments as `Docker <https://www.docker.com/>`__ containers. The *docker* unpacker (``reprounzip docker``) is responsible for such integration and it assumes that Docker is already installed in the current environment.

You can pass arguments to the ``docker(1)`` program by using the ``--docker-option`` option to the ``setup`` or ``run`` commands.

Thanks to Docker's image layers feature, you can easily go back to the initial image after having run commands in the environment or replaced input files. To do that, use the ``reset`` command::

    $ reprounzip docker reset <path>

..  note:: This unpacker is **not** distributed with `reprounzip`; it is a separate package that should be installed before use (see :ref:`install`).

..  _unpacker-commands:

Using an Unpacker
=================

Once you have chosen (and installed) an unpacker for your machine, you can use it to setup and run a packed experiment. An unpacker creates an **experiment directory** in which the working files are placed; these can be either the full filesystem (for *directory* or *chroot* unpackers) or other content (e.g.: a handle on a virtual machine for the *vagrant* unpacker); for the *chroot* unpacker, it might have mount points. To make sure that you free all resources and that you do not damage your environment, you should **always use the destroy command** to delete the experiment directory, not just merely delete it manually. See more information about this command below.

All the following commands need to state which unpacker is being used (i.e., ``reprounzip directory`` for the `directory` unpacker, ``reprounzip chroot`` for the `chroot` unpacker, ``reprounzip vagrant`` for the `vagrant` unpacker, and ``reprounzip docker`` for the `docker` unpacker). For the purpose of this documentation, we will use the `docker` unpacker; to use a different one, just replace ``docker`` in the following with the unpacker of your interest.

..  seealso:: :ref:`unpacked-format` provides further detailed information on unpackers.

Setting Up an Experiment Directory
++++++++++++++++++++++++++++++++++

..  note:: Some unpackers require an Internet connection during the ``setup`` command, to download some of the support software or the packages that were not packed. Make sure that you have an Internet connection, and that there is no firewall blocking the access.

To create the directory where the execution will take place, the ``setup`` command should be used::

    $ reprounzip docker setup <bundle> <path>

where `<path>` is the directory where the experiment will be unpacked, i.e., the experiment directory.

Note that, once this is done, you should only remove `<path>` with the `destroy` command described below: deleting this directory manually might leave files behind, or even damage your system through bound filesystems.

The other unpacker commands take the `<path>` argument; they do not need the original bundle for the reproduction.

Reproducing the Experiment
++++++++++++++++++++++++++

After creating the directory, the experiment can be reproduced by issuing the ``run`` command::

    $ reprounzip docker run <path>

which will execute the experiment inside the experiment directory. Users may also change the command line of the experiment by using ``--cmdline``::

    $ reprounzip docker run <path> --cmdline <new-command-line>

where `<new-command-line>` is the modified command line. This is particularly useful to reproduce and test the experiment under different input parameter values. Using ``--cmdline`` without an argument only prints the original command line.

If the bundle contains multiple `runs` (separate commands that were packed together), all the runs are reproduced. You can also provide the id of the run or runs to be used::

    $ reprounzip docker run <path> <run-id>
    $ reprounzip docker run <path> <run-id> --cmdline <new-command-line>

For example::

    $ reprounzip docker run unpacked-experiment 0-1,3  # First, second, and fourth runs
    $ reprounzip docker run unpacked-experiment 2-  # Third run and up
    $ reprounzip docker run unpacked-experiment compile,test  # Runs named 'compile' and 'test', in this order

If the experiment involves running a GUI tool, the graphical interface can be enable by using ``--enable-x11``::

    $ reprounzip docker run <path> --enable-x11

which will forward the X connection from the experiment to the X server running on your machine. In this case, make sure you have a running X server.

If the experiment is a server, for example a website, a database management system, etc, you can expose ports from the experiment on your local machines. This is not required for the `directory` and `chroot` unpackers, since they offer no isolation of the network; for the `docker` and `vagrant` unpackers, use the ``--expose-port`` option::

    $ reprounzip docker run --expose-port 8000:80 unpacked-experiment  # Expose TCP port 80 (HTTP) of the experiment at http://localhost:8000/
    $ reprounzip docker run --expose-port 3000 unpacked-experiment  # Expose TCP port 3000 of the experiment at localhost:3000
    $ reprounzip docker run --expose-port 5553:53/udp unpacked-experiment  # Expose UDP port 53 of the experiment at localhost:5553

Note that in some situations, you might want to pass specific environment variables to the experiment, for example to set execution limits or parameters (such as OpenMPI information). To that effect, you can use the ``--pass-env VARNAME`` option to pass variables from the current machine, overriding the value from the original packing machine (`VARNAME` can be a regex). You can also set a variable to any value using ``--set-env VARNAME=value``. For example::

    $ reprounzip docker run unpacked-experiment --pass-env 'OMPI_.*' --pass-env LANG --set-env DATA_SERVER_ADDRESS=localhost

..  versionadded:: 1.0.3
    The ``--pass-env`` and ``-set-env`` options.

Removing the Experiment Directory
+++++++++++++++++++++++++++++++++

The ``destroy`` command will unmount mounted paths, destroy virtual machines, free container images, and delete the experiment directory::

    $ reprounzip docker destroy <path>

Make sure you always use this command instead of simply deleting the directory manually.

..  _unpacker-input-output:

Managing Input and Output Files
+++++++++++++++++++++++++++++++

When tracing an experiment, ReproZip tries to identify which are the input and output files of the experiment. This can also be adjusted in the configuration file before packing.
If the unpacked experiment has such files, ReproZip provides some commands to manipulate them.

First, you can list these files using the ``showfiles`` command::

    $ reprounzip showfiles <path>
    Input files:
        program_config
        ipython_config
        input_data
    Output files:
        rendered_image
        logfile

To replace an input file with your own, `reprounzip`, you can use the ``upload`` command::

    $ reprounzip docker upload <path> <input-path>:<input-id>

where `<input-path>` is the new file's path and `<input-id>` is the input file to be replaced (from ``showfiles``). This command overwrites the original path in the environment with the file you provided from your system. To restore the original input file, the same command, but in the following format, should be used::

    $ reprounzip docker upload <path> :<input-id>

Running the ``showfiles`` command shows what the input files are currently set to::

    $ reprounzip showfiles <path> --input
    Input files:
        program_config
            (original)
        ipython_config
            C:\Users\Remi\Documents\ipython-config

In this example, the input `program_config` has not been changed (the one bundled in the ``.rpz`` file will be used), while the input `ipython_config` has been replaced.

After running the experiment, all the generated output files will be located under the experiment directory. To copy an output file from this directory to another desired location, use the ``download`` command::

    $ reprounzip docker download <path> <output-id>:<output-path>

where `<output-id>` is the output file to be copied (from ``showfiles``) and `<output-path>` is the desired destination of the file. If an empty destination is specified, the file will be printed to stdout::

    $ reprounzip docker download <path> <output-id>:

You can also omit the colon ``:`` altogether to download the file to the current directory under its original name::

    $ reprounzip docker download <path> <output-id>

or even use ``--all`` to download every output file to the current directory under their original names.

Note that the ``upload`` command takes the file id on the right side of the colon (meaning that the path is the origin, and the id is the destination), while the ``download`` command takes it on the left side (meaning that the id is the origin, and the path is the destination). Both commands move  data from left to right.

..  versionadded:: 1.0.4
    Allow ``download <output-id>`` (no explicit destination), and add ``--all``.

..  seealso:: :ref:`Why can’t 'reprounzip' get my output files after reproducing an experiment? <moving-outputs>`

Running the Experiment in VisTrails
+++++++++++++++++++++++++++++++++++

In addition to reproducing the experiment, you may want to edit its dataflow by inserting your own processes between and around the experiment steps, or even by connecting multiple ReproZip'd experiments. However, manually managing the experiment workflow (with the help of ``reprounzip upload/download`` commands) can quickly become painful.

To allow users to easily manage these workflows, `reprounzip` provides a plugin for the `VisTrails <https://www.vistrails.org/>`__ scientific workflow management system, which has easy-to-use interfaces to run and modify a dataflow. See :ref:`vistrails` for more information.

Further Considerations
======================

Reproducing Multiple Execution Paths
++++++++++++++++++++++++++++++++++++

The *reprozip* component can only guarantee that *reprounzip* will successfully reproduce the same execution path that the original experiment followed. There is no guarantee that the experiment won't need a different set of files if you use a different configuration; if some of these files were not packed into the ``.rpz`` package, the reproduction may fail.
