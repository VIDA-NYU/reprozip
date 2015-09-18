..  _troubleshooting:

Troubleshooting
***************

The best way to start solving an issue in ReproZip is probably to look at the log messages. Some messages are not displayed by default when running ReproZip, but you can use the ``--verbose`` (or ``-v``) flag to display them. In addition, all the log messages are stored under ``$HOME/.reprozip/log``.

Please feel free to contact us at reprozip-users@vgc.poly.edu if you encounter issues while using ReproZip.

------------

..  _file_id:

:Issue: **"** `reprozip` **does not identify my input/output file."**
:Diagnosis: ReproZip uses some heuristics to identify an input or output file. However, this is only intended to be a starting point, since these heuristics may fail.
:Solution: You should check the configuration file and edit the ``inputs_outputs`` section if necessary; giving readable names to input/output files also helps during reproduction. Please refer to :ref:`packing-config` for more information.

------------

..  _systemd:

:Issue: **"None of my files are packed when tracing a daemon."**
:Diagnosis: If you are starting the daemon via the `service` tool, it might be calling `init` over a client/server connection. In this situation, ReproZip will successfully pack the client, but anything the server (`init`) does will not be captured.
:Solution: You can still trace the binary or a non-systemd `init` script directly. For example, instead of::

               $ reprozip trace service mysql start

           you can trace either the `init` script::

               $ reprozip trace /etc/init.d/mysql start

           or the binary::

               $ reprozip trace /usr/bin/mysqld

           Note that, if you choose to trace the binary, you need to figure out the right command line options to use.
           Also, make sure that systemd is not called, since ReproZip and systemd currently do not get along well.

------------

..  _moving-outputs:

:Issue: **"** `reprounzip` **cannot get an output file using** ``download`` **after reproducing the experiment."**
:Diagnosis: This is probably the case where this output file does not have a fixed path name. It is common for experiments to dynamically choose where the outputs should be written, e.g.: by putting the date and time in the filename. However, ReproZip uses filenames in the ``inputs_outputs`` section of the configuration file to detect those when reproducing the experiment: if the name of the output file when reproducing is different from when it was originally packed, ReproZip cannot detect these as output files, and therefore, cannot get them through the ``download`` command.
:Solution: The easiest way to solve this issue is to re-pack the experiment: write a simple bash script that runs the experiment and either renames outputs or creates symbolic links to them with known filenames; then, trace this script (instead of the actual entry-point of your experiment) and specify these fixed path names in the ``inputs_outputs`` section of the configuration file.

------------

..  _pycrypto_windows:

:Issue: **"** `reprounzip-vagrant` **installation fails with error** ``Unable to find vcvarsall.bat`` **on Windows."**
:Diagnosis: Python is trying to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`__, one of the dependencies of `reprounzip-vagrant`, but there is no C compiler available.
:Solution: You can either build PyCrypto from source, or follow the instructions on `this website <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`__ to get the non-official binaries.

------------

..  _compiler_mac:

:Issue: **"** `reprounzip-vagrant` **installation fails with error** ``unknown argument: '-mno-fused-madd'`` **on Mac OS X."**
:Diagnosis: This is an issue with the Apple LLVM compiler, which treats unrecognized command-line options as errors.
:Solution: As a workaround, before installing `reprounzip-vagrant`, run the following::

               $ export CFLAGS="-Wno-error=unused-command-line-argument-hard-error-in-future"

           Then, re-install `reprounzip-vagrant`::

               $ pip install -I reprounzip-vagrant

           Or use the following command in case you want all the available plugins::

               $ pip install -I reprounzip[all]

------------

:Issue: **"The experiment fails with** ``Error: Can't open display: :0`` **when trying to reproduce it."**
:Diagnosis: The experiment probably involves running a GUI tool.
:Solution: The `reprounzip` component supports GUI tools, but it is not enabled by default; add the flag ``--enable-x11`` to the ``run`` command to enable it. See :ref:`gui-tools` for more information.

------------

..  _directory_error:

:Issue: **"The experiment run with** `reprounzip directory` **fails to find a file that has been packed."**
:Diagnosis: The `directory` unpacker does not provide any isolation from the filesystem: if the experiment being reproduced use absolute paths, these will point outside the experiment directory, and files may not be found.
:Solution: Make sure that the experiment does not use any absolute paths: if only relative paths are used internally and in the command line, ``reprounzip directory`` should work. As an alternative, you can use other unpackers (e.g.: ``reprounzip chroot`` and ``reprounzip vagrant``) that work in the presence of hardcoded absolute paths.

------------

..  _distribnotfound:

:Issue: **"** `reprounzip` **fails with** ``DistributionNotFound`` **errors."**
:Diagnosis: You probably have some plugins left over from a previous installation.
:Solution: Be sure to upgrade or remove outdated plugins when you upgrade `reprounzip`. The following command may help::

               $ pip install -U reprounzip[all]

------------

:Issue: **"** `reprounzip` **shows** ``running in chroot, ignoring request`` **."**
:Diagnosis: This message comes from the systemd client, which will probably not work with ReproZip.
:Solution: In this case, the experiment should be re-packed without using systemd (see :ref:`this issue <systemd>` for more information).

------------

:Issue: **"** ``reprounzip vagrant setup`` **fails to resolve a host address."**
:Diagnosis: When running ``reprounzip vagrant setup``, if you get an error similar to this::

                ==> default: failed: Temporary failure in name resolution.
                ==> default: wget: unable to resolve host address ...

            there is probably a firewall blocking the Vagrant VM to have Internet connection; the VM needs Internet connection to download required software for setting up the experiment for you.
:Solution: Make sure that your anti-virus/firewall is not causing this issue.

------------

..  _nosuchfile:

:Issue: **"** ``reprounzip run`` **fails with** ``no such file or directory`` **or similar."**
:Diagnosis: This error message may have different reasons, but it often means that a specific version of a library or a dynamic linker is missing:

            1. If you are requesting `reprounzip` to install software using the package manager (by running ``reprounzip installpkgs``), it is possible that the software packages from the package manager are not compatible with the ones required by the experiment.
            2. If, while packing, the user chose not to include some packages, `reprounzip` will try to install the ones from the package manager, which may not be compatible.
            3. If you are using ``reprounzip vagrant`` or ``reprounzip docker``, ReproZip may be failing to detect the closest base system for unpacking the experiment.
:Solution:
            1. Use the files inside the experiment package to ensure compatibility.
            2. Contact the author of the ReproZip package to ask for a new package with all software packages included.
            3. Try a different base system that you think it is closer to the original one by using the option ``--base-image`` when running these unpackers.

------------

:Issue: **"There are warnings from requests/urllib3 when running ReproZip."**
        ::

            /usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/util/ssl_.py:79:
            InsecurePlatformWarning: A true SSLContext object is not available. This
            prevents urllib3 from configuring SSL appropriately and may cause certain SSL
            connections to fail. For more information, see
            https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning.

:Diagnosis: Most Python versions are insecure, because they do not validate SSL certificates, thus generating these warnings.
:Solution: If you are using Python 2.7.9 and later, you shouldn't be affected, but if you see ``InsecurePlatformWarning``, you can run ``pip install requests[security]``, which should bring in the missing components.
