..  _packing-experiments:

Using *reprozip*
****************

The *reprozip* component is responsible for packing an experiment. In ReproZip, we assume that the experiment can be executed by a single command line, preferably with no GUI involved (please refer to :ref:`further-information` for additional information regarding different types of experiments).

There are three steps when packing an experiment with *reprozip*: :ref:`tracing the experiment <packing-trace>`, :ref:`editing the configuration file <packing-config>`, if necessary, and :ref:`creating the reproducible package for the experiment <packing-pack>`. Each of these steps is explained in more details below. Note that *reprozip* is only available for Linux distributions.

..  _packing-trace:

Tracing an Experiment
=====================

First, *reprozip* needs to trace the operating system calls used by the experiment, so as to identify all the necessary information for its future re-execution, such as binaries, files, library dependencies, and environment variables.

The following command is used to trace an experiment::

    $ reprozip trace <command-line>

where `<command-line>` is the command line used to execute the experiment. By running this command, *reprozip* executes the experiment and uses `ptrace` to trace all the system calls issued, storing them in an SQLite database.

By default, if the operating system is Debian or Debian-based (e.g.: Ubuntu), *reprozip* will also try to automatically identify the distribution packages that the files come from, using the available `package manager <http://en.wikipedia.org/wiki/Dpkg>`_ of the system. This is useful to provide more detailed information about the dependencies, as well as to further help when reproducing the experiment; however, the *trace* command can take some time doing that after the experiment has finished, depending on the number of file dependencies that the experiment has. To disable this feature, users may use the flag *--dont-identify-packages*::

    $ reprozip trace --dont-identify-packages <command-line>

The database, together with a *configuration file* (see below), are placed in a directory named ``.reprozip``, created under the path where the *reprozip* command was issued.

..  _packing-config:

Editing the Configuration File
==============================

The configuration file, which can be found in ``.reprozip/config.yml``, contains all the information necessary for creating the experiment package. It is created by the tracer, and drives the packing step. You probably don't need to change anything, as the automatically-generated file is probably sufficient to generate the package, however you may edit this file prior to the creation of the package in order to add or remove files. This can be particularly useful, for instance, to remove big files that can be obtained elsewhere when reproducing the experiment, so as to keep the size of package small, and also to remove sensitive information that the experiment may use. The configuration file can also be used to edit the main command line, as well as to add or remove environment variables.

The first part of the configuration file gives general information with respect to the experiment execution, including the command line, environment variables, main input and output files, and machine information::

    # Run info
    version: <reprozip-version>
    runs:
    - architecture: <machine-architecture>
      argv: <command-line-arguments>
      binary: <command-line-binary>
      distribution: <linux-distribution>
      environ: <environment-variables>
      exitcode: <exit-code>
      gid: <group-id>
      hostname: <machine-hostname>
      input_files: <input-files>
      output_files: <output-files>
      system: <system-kernel>
      uid: <user-id>
      workingdir: <working-directory>

If necessary, users may change the command line parameters by editing `<command-line-arguments>`, and add or remove environment variables by editing `<environment-variables>`. Other attributes should mostly not be changed.

The next section in the configuration file shows the files to be packed. If the software dependencies were identified by the package manager of the system during the `trace` command execution, they will be listed under `packages`; the file dependencies not identified in software packages are listed under `other_files`::

    packages:
      - name: <package-name>
        version: <package-version>
        size: <package-size>
        packfiles: <include-package>
        files:
          # Total files used: <used-files-size>
          # Installed package size: <package-size>
          <files-list>
      - name: ...
      ...

    other_files:
      <files-list>

The attribute `packfiles` can be used to control which software packages will be packed: its default value is `true`, but users may change it to `false` to inform *reprozip* that the corresponding software package should not be included. To remove a file that was not identified as part of a package, users can simply remove it from the list under `other_files`.

Last, users may add file patterns under `additional_patterns` to include other files that they think it will be useful for a future reproduction. As an example, the following would add everything under ``/etc/apache2/`` and all the Python files of all users from LXC containers (contrieved example)::

    additional_patterns:
      - /etc/apache2/**
      - /var/lib/lxc/*/rootfs/home/**/*.py

Note that users can always reset the configuration file to its initial state by running the following command::

    $ reprozip reset

..  _packing-pack:

Creating a Package
==================

After tracing the experiment and optionally editing the configuration file, the experiment package can be created by issuing the command below::

    $ reprozip pack <package-name>

where `<package-name>` is the name given to the package. This command generates a ``.rpz`` file in the current directory, which can then be sent to others so that the experiment can be reproduced. For more information regarding the unpacking step, please see :ref:`unpacking-experiments`.

..  _further-information:

Further Considerations
======================

Packing Multiple Command Lines
++++++++++++++++++++++++++++++

ReproZip can only pack one command line execution per package. Therefore, if an experiment comprises many command line executions, users should create a **script** that combines all these command lines, and pack the script execution with *reprozip*.

Packing GUI and Interactive Tools
+++++++++++++++++++++++++++++++++

Currently, ReproZip cannot ensure that GUI interfaces will be correctly reproduced (support is coming soon), so we recommend packing tools in a non-GUI mode for a successfull reproduction.

Additionally, there is no restriction in packing interactive experiments (i.e., experiments that require input from users). Note, however, that ReproZip packs the execution path followed during the `trace` command execution. Therefore, during reproduction, if the interactive inputs chosen by the user are different from the ones used in the packing step, other dependencies might be required that ReproZip didn't know about (and thus didn't pack).

Capturing Useful Parameters and Input Files
+++++++++++++++++++++++++++++++++++++++++++

ReproZip traces the *execution* of the experiment; concretely, this means that, for compiled programming languages, it captures the binaries rather than the source code. As a consequence, if the experiment has important parameters and input files that are hardcoded, these will not be able to be varied and explored when reproducing the execution, once the source code is not included in the package. It is thus recommended that users **expose all useful parameters as command line arguments or in an input file** for the experiment, since *reprounzip* allows users to easily change the argument values for the experiment reproduction (see :ref:`unpacking-experiments` for more information on reproducing experiments).

Capturing Connections to Servers
++++++++++++++++++++++++++++++++

Communication with remote servers is outside the scope of ReproZip: when reproducing an execution, the experiment will try to connect to the same server, which may or may not fail depending on the status of the server at the moment of the reproduction. However, if the experiment uses a local server (e.g.: database) that can the user has control over, this server can also be captured, together with the experiment, to ensure that the connection will succeed. Users should create a **script** to:

* start the server,
* execute the experiment, and
* stop the server,

and use *reprozip* to trace the whole script, rather than the experiment itself. In this way, ReproZip is able to capture the local server as well, which ensures that the server will be alive at the time of the reproduction.

Excluding Sensitive and Third-Party Information
+++++++++++++++++++++++++++++++++++++++++++++++

ReproZip automatically tries to identify log and temporary files, removing them from the package, but the configuration file should be edited to remove any sensitive information that the experiment uses, or any third-party file/software that should not be distributed. Note that the ReproZip team is **not responsible** for personal and non-authorized files that may get distributed in a package; users should double-check the configuration file and their package before sending it to others.

Identifying Output Files
++++++++++++++++++++++++

ReproZip tries to automatically identify the main output files generated by the experiment during the `trace` command to provide useful interfaces for users during the unpacking step. However, if the experiment creates unique names for its outputs every time it is executed (e.g.: names with current date and time), the *reprounzip* component will not be able to correctly detect these; it assumes that input and output files don't move. In this case, handling output files will fail; it is recommended that users modify their experiment (or use a wrapper script) to generate a symbolic link (with a default name) that always points to the latest result, and use that as the output file's path in the configuration.
