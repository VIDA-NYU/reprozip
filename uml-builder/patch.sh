#!/bin/bash

set -e

###################################################
## Patch the Linux source tree with AUFS support ##
###################################################

# Target Kernel Version
VERSION=$(grep '^VERSION\s*=' Makefile | cut -d= -f2 | sed 's/\s//g')
PATCHLEVEL=$(grep '^PATCHLEVEL\s*=' Makefile | cut -d= -f2 | sed 's/\s//g')
KVER=$VERSION.$PATCHLEVEL
# Temporary Location
#TMPGIT=`mktemp -d`
GIT=aufs-aufs3-standalone
GIT_URL=git://git.code.sf.net/p/aufs/aufs3-standalone
BINPREFIX=aufs3-

if [ "x$VERSION" = "x4" ]; then
    GIT=patches/aufs-aufs4-standalone
    GIT_URL=git://github.com/sfjro/aufs4-standalone.git
    BINPREFIX=aufs4-
fi

# Clone AUFS repo
if [ ! -d $GIT ]; then
    which git || (apt-get update && apt-get install -y git)
    git clone -n $GIT_URL $GIT
fi

# Checkout AUFS branch
pushd $GIT
git checkout origin/aufs$KVER
popd

# Copy in files
cp -r $GIT/{Documentation,fs} ./
cp $GIT/include/uapi/linux/aufs_type.h ./include/uapi/linux/aufs_type.h

# Apply patches
cat $GIT/${BINPREFIX}{base,kbuild,loopback,mmap,standalone}.patch | patch -p1

printf "Patched Kernel $KVER with AUFS support!"
