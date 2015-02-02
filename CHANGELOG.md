Changelog
=========

0.5.2 (???)
-----------

Bugfixes:
* Fixes `debug` log messages not being printed
* Pressing Ctrl+C wouldn't stop package identification with KeyboardInterrupt
* Fixes an error message while destroying a docker experiment

0.5.1 (2014-12-18)
------------------

Bugfixes:
* Goes back to pack format 0.4: generates `.rpz` files readable by older
  reprounzip versions
* Fixes experiment not having a PTY in some conditions
* Rewrite absolute paths on command-line for directory unpacker

Features:
* Python 2.6 support for reprounzip (except 'graph')
* Makes error messages more readable
* Default trace directory renamed from `.reprozip` to `.reprozip-trace`
* Adds a log file under $HOME/.reprozip/log
* reprounzip-vagrant will use 'ssh' executable if it's available; should be
  more reliable, especially on Windows
* Automatically collects usage information. Nothing will be sent before you
  opt-in, and we made sure to only collect general details

0.5 (2014-11-24)
----------------

Features:
* All reprounzip plugins can be installed with `pip install reprounzip[all]`
* Various improvements to interactive vagrant console
* Adds support for generic plugins (alongside unpackers)
* Adds reprounzip-vistrails plugin
* Pressing Ctrl+C while tracing won't abort anymore; press it twice for SIGKILL

0.4.1 (2014-10-06)
------------------

Bugfixes:
* reprounzip showed duplicated logging messages
* Makes 'run' commands not fail if the command returns an error code
* Unicode issues with Vagrant on Windows Python 3
* Warning for files read then written didn't show the filenames
* Fixes resetted input files breaking 'showfiles'

Features:
* 'docker upload' command
* Adds signals (currently unused, needed for future plugins)

0.4 (2014-09-15)
----------------

Bugfixes:
* Copying files from host to chroot when some packages where not packed
* Don't use the full command path in directory's script
* Fixes socketcall() handling

Features:
* Displays a warning for READ_THEN_WRITTEN files
* chroot restores files' owner/group
* Adds 'reprounzip info' command
* Better error messages when trying to unpack on incompatible system
* Identifies input files, which can be replaced ('upload' operation)
* Identifies output files, which can be retrieved ('download' operation)
* New command-line interface for unpackers, with setup/run/destroy; you can now
  do everything through reprounzip
* Vagrant now defaults to --use-chroot`, added --no-use-chroot
* Adds --summary and --missing to installpkgs
* Adds Docker unpacker (no uploading support yet)

0.3.2 (2014-08-28)
------------------

(reprounzip only)

Bugfixes:
* Once busybox was in the local cache, setting it up could crash
* 'script.sh' files were not set as executable

0.3.1 (2014-08-26)
------------------

(reprozip only)

Bugfixes:
* Don't crash when packing an experiment that wrote in temporary directories

0.3 (2014-07-28)
----------------

Bugfixes:
* Handles Linux changing thread id to thread leader's on `execve()`
* Correctly handles processes dying from signals (e.g. SEGV)
* Fixes case of rt_sigreturn

Features:
* Database stores `is_directory` field
* Handles `mkdir()`, `symlink()`
* Forces pack to have a `.rpz` extension
* Displays a warning when the process uses `connect()` or `accept()`
* Improved logging
* Handles i386 compatibility mode on x86_64
* Handles *at() variants of system calls with AT_FDCWD

0.2.1 (2014-07-11)
------------------

Bugfixes:
* 'pack' no longer stop if a file is missing
* Do not attempt to pack files from /proc or /dev
* Stops vagrant without --use-chroot from overwriting files
* Downloads busybox instead of using the host's /bin/sh
* Correctly packs the dynamic linkers from the original machine
* The tracer no longer considers `execve()` to always happen before other accesses
* Fixes pytracer forking the Python process if the executable cannot be found
* Improves signal handling (but bugs might still exist with `SIGSTOP`)
* Fixes a bug if a process resumed before its creator (race condition)

Features:
* -v flag also controls C tracer's verbosity
* Detects (but doesn't handle yet) i386 compatibility and x32 mode on x86_64
* Stores working directories and exit codes of all processes in database
* Added `reprozip reset [-d dir]` to reset the configuration file from the database

0.2 (2014-06-18)
----------------

First version of the rewritten ReproZip, that uses ptrace. Basic functionality.

0.1 (2013-06-25)
----------------

SystemTap-based version of ReproZip.
