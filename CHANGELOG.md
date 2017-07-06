Changelog
=========

1.0.10 (???)
------------

Bugfixes:
* Correctly escape shell commands containing backticks
* Overwrite tty prompt works correctly on Python 3
* Fix /proc in vagrant-chroot and chroot having outside mounts
* Fix ANSI escapes showing in Qt terminal dialog
* Fix reprozip combine crash on Python 3.6 (patch from James Clarke)
* Using `graph --packages drop` together with `--json` no longer crashes

Enhancements:
* Add `--docker-cmd` to reprounzip-docker to select the Docker command (for example `--docker-cmd="sudo docker"`)
* Implement `--expose-port` option for Vagrant and Docker (no need for `--docker-option=-p...`)
* Add docker-machine support to GUI (select which machine to use)
* Better binaries for MacOS
* Automatically register reprounzip-qt to open .RPZ files on Linux
* Register ReproUnzip with Windows from installer
* Add icon from @heng2j

1.0.9 (2017-01-10)
------------------

Bugfixes:
* Fix CentOS Docker image versions
* Remove Fedora Docker images, they don't have tar
* Do include .pyc files in packages, so reproduction take same code path
* Don't use the experiment's resolv.conf file
* Fix handling of files opened in read-write mode

1.0.8 (2016-10-07)
------------------

Behavior changes:
* No longer default to overwriting trace directories. ReproZip will ask what to do or exit with an error if one of --continue/--overwrite is not provided

Bugfixes:
* Fix an issue identifying Debian packages when a file's in two packages
* Fix Python error `Mixing iteration and read methods would lose data`
* Fix reprounzip info showing some numbers as 0 instead of hiding them in non-verbose mode
* Another fix to X server IP determination for Docker

Enhancements:
* New GUI for reprounzip, allowing one to unpack without using the command-line
* Add filters to remove some common files types from packed files (.pyc) or detected input files (.py, .so, ...)
* Add JSON output format to `reprounzip info`
* Allow using the Virtualbox display to reproduce X11-enabled experiments

1.0.7 (2016-08-22)
------------------

Bugfixes:
* Correctly show an error message if ptrace is unavailable
* Make Docker & Vagrant setup much faster

Enhancements:
* Add support for RPM-based distributions, in addition to Debian-based

1.0.6 (2016-06-25)
------------------

(reprounzip-vistrails didn't change)

Bugfixes:
* Fixes error using Docker with `--enable-x11` on Python 3

Enhancements:
* `docker run` gets a `--detach` command, to keep the container running (useful for starting servers on remote machines)
* Restrictions on upload and download commands have been relaxed, in particular it is possible to download input files as well as output files
* Don't compress outer tar (data is still compressed); this should make some operations (like `reprounzip info`) faster
* Add `reprozip combine`, useful to combine multiple traces into one (as different runs). Handy if running distributed experiments on shared filesystem (MPI)

1.0.5 (2016-04-07)
------------------

(reprounzip-vagrant didn't change)

Bugfixes:
* Correctly download parameters from server
* More reliable way of determining X server IP without using /bin/ip

1.0.4 (2016-03-10)
------------------

Behavior changes:
* reprounzip will no longer run on Python 2.6

Bugfixes:
* Fixes file download not using cache if URL is HTTPS
* Fixes unpacking with directory or chroot for some multi-step packages

Features:
* Add `--docker-option` to pass raw options to Docker
* You can use `run` or `run -` to run every run, regardless of their number
* Allow `download <name>`, shortcut for `download <name>:./<name>` (downloads to current directory, keep name)
* Allow `download --all`
* Add `--input` and `--output` to showfiles
* Implement `vagrant suspend` command
* Do file downloads with [requests](http://python-requests.org/)
* Download a parameter file to update URLs and image names without waiting for the next ReproZip version

1.0.3 (2015-12-02)
------------------

Bugfixes:
* You could get a traceback with some unpackers (not Vagrant) on some packages that explicitely pack the / directory
* Some environment variables prevented running, such as bash exported functions.

Features:
* Remove setup directory if setup fails, so you can run setup again without gettin `target directory exists`
* Add `--set-env` and `--pass-env` to run

1.0.2 (2015-10-26)
------------------

Bugfixes:
* You can now use X11 forwarding even with a remote Docker daemon
* reprounzip-vagrant now works in paths containing spaces

1.0.1 (2015-10-12)
------------------

Bugfixes:
* Files opened through a shebang were stored with a wrong process number
* Running with Docker on non-Linux machine didn't work (e.g. docker-machine); now only X11 doesn't work.
* Some fixes to the graph command

Features:
* `--memory` option for `reprounzip vagrant setup`, to set the VM's RAM.

1.0.0 (2015-09-30)
------------------

Behavior change:
* .rpz pack format changed (version 1 -> 2). Pack is now uncompressed, data is in a nested TGZ archive; allows faster retrieval of metadata (config & trace).
* reprozip trace warnings are now info messages; won't show up without -v

Bugfixes:
* After restarting a Vagrant machine, /dev and /proc wouldn't be mounted anymore
* Files or links referenced in a shebang could be missed by the tracer

Features:
* Runs in the configuration file now have an 'id' field, that will be shown by 'reprounzip info' and can be selected when running
* Reworked `reprounzip graph`: level of details, regex filters & replace, JSON output
* Added *run* argument to `reprounzip showfiles`, to show inputs & outputs of a single run

0.7.2 (2015-08-24)
------------------

Behavior change:
* reprounzip-docker will now re-use the resulting image from the previous run when running again, instead of starting from scratch; a 'reset' command has been added to undo runs and uploads.

Bugfixes:
* Couldn't reset an input file to the original (packed) file on Python 3
* Don't show a warning about network connections when they didn't succeed
* Hide traceback when failing because Vagrant is not installed
* Fix input/output file detection assigning files to the same run
* Fix selecting multiple runs in 'docker run'

Features:
* Display the relative portion of the path when unhandled xxx_at() syscalls are used, to give an idea of what's been missed
* Add --dont-find-inputs-outputs to reprozip trace and reset, so you can clear that out if too many files would be selected (or if you don't use the feature)
* Rewrote reprounzip-vistrails plugin; uses a proper VisTrails package that now lives in the VisTrails distribution.
* Check pack format in unpackers; won't try to unpack version 2
* It is now possible to select multiple runs with `unpackername run 1-4`

0.7.1 (2015-07-14)
------------------

(reprozip only)

Bugfixes:
* Files (or links) created with rename, link or symlink then read will no longer be packed.
* A buffer overflow could happen in the log module, for instance when the experiment passes a very long argument to execve (over 4kB in a single argument) and running in debug mode (-v -v)


0.7 (2015-07-07)
----------------

Behavior change:
* No longer accept passing `-v` after the subcommand; use `reprozip -v testrun ...`, not `reprozip testrun -v`.
* Rely on `PTHREAD_EVENT_EXEC` to handle `execve()`. Makes tracing more reliable, and enable it to behave correctly on weird kernels (like UML).
* Rely on `PTRACE_EVENT_FORK` to handle `fork`/`vfork`/`clone`. Fixes vfork() deadlocking under trace.
* Completely changed the structure of input and output files (old packs will still be loaded, but new packs are not retro-compatible).
* Using one of the `run` commands without specifying a number will no longer default to running all of them; it will error out if there are multiple runs.

Bugfixes:
* Fix insertion speed in SQLite3 database

Features:
* Makes VMs (Vagrant or Docker)  more resilient to massive breakage of system libraries (obliterating /lib or /usr, when using very different operating systems) by putting busybox in / and using [rpzsudo](https://github.com/remram44/static-sudo).
* No longer use `dpkg -S` to identify packages, do a single pass over internal dpkg database (this is considerably faster).

0.6.4 (2015-06-07)
------------------

(reprounzip-vistrails didn't change)

Bugfixes:
* Tracer: correctly handle `chdir()` in multi-threaded processes
* Fix leaked file descriptors, eventually making SQLite3 fail
* No longer exceed cmdline length in Dockerfile in big .RPZ pack
* Fixes `check_output` call when running Docker (not available in Python 2.6)
* Fixes installation of `sudo` failing if original machine wasn't Debian
* Don't make TAR error status fatal in Dockerfile (might not run; this is needed because Docker mount some files in the container that can't be overwritten)

0.6.3 (2015-05-06)
------------------

(reprounzip and plugins only)

Bugfixes:
* Fixes reprounzip-vistrails failing because of reporting
* Fixes reprounzip-vistrails not escaping correctly in XML in some conditions
* Fixes docker run failing to read Docker's JSON output on Python 3
* Fixes reprounzip chroot mounting too many filesystems
* Fixes typo stopping reprounzip from running on unsupported distribs

Features:
* Adds Debian 8 'Jessie' to Vagrant boxes & Docker images
* Adds Ubuntu 15.04 'Vivid' to Vagrant boxes & Docker images

0.6.2 (2015-03-16)
------------------

(reprozip only)

Bugfixes:
* Fixes installation on Python 3 with 7-bit locale
* Fixes reprozip not showing traceback on exception
* Fixes bug with multiple runs (`trace --continue`)

0.6.1 (2015-02-17)
------------------

(reprozip only)

Bugfixes:
* Fixes an overflow in _pytracer for some syscalls.

0.6 (2015-02-11)
----------------

(reprounzip-vistrails didn't change)

Bugfixes:
* Fixes `debug` log messages not being printed
* Pressing Ctrl+C wouldn't stop package identification with KeyboardInterrupt
* Fixes an error message while destroying a docker experiment
* Fixes docker not installing packages if they were packed
* Fixes docker always reporting exit status 0

Features:
* Adds `--install-pkgs` options to `docker setup`, to prefer installing
from package manager over unpacking the packed files
* With vagrant or docker, original machine hostname is restored
* X11 support for chroot, vagrant and docker unpackers

0.5.1 (2014-12-18)
------------------

(reprounzip-vistrails didn't change)

Bugfixes:
* Goes back to pack format 0.4: generates `.rpz` files readable by older reprounzip versions
* Fixes experiment not having a PTY in some conditions
* Rewrite absolute paths on command-line for directory unpacker

Features:
* Python 2.6 support for reprounzip (except 'graph')
* Makes error messages more readable
* Default trace directory renamed from `.reprozip` to `.reprozip-trace`
* Adds a log file under $HOME/.reprozip/log
* reprounzip-vagrant will use 'ssh' executable if it's available; should be more reliable, especially on Windows
* Automatically collects usage information. Nothing will be sent before you opt-in, and we made sure to only collect general details

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
* New command-line interface for unpackers, with setup/run/destroy; you can now do everything through reprounzip
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
