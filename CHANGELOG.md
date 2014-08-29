Changelog
=========

dev (???)
---------

Bugfixes:
* Copying files from host to chroot when some packages where not packed
* Don't use the full command path in directory's script

Features:
* Displays a warning for READ_THEN_WRITTEN files
* Identifies input and output files
* Adds 'reprounzip info' command
* Better error messages when trying to unpack on incompatible system
* Vagrant now defaults to --use-chroot`, added --no-use-chroot
* Adds --summary and --missing to installpkgs

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
