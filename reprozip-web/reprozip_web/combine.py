# Copyright (C) 2022 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import contextlib
import logging
import os.path
import shutil
import tarfile
import time
import zipfile


logger = logging.getLogger('reprozip_web')


def combine_tar(input_tar, wacz_filename, output_filename):
    if not os.path.isfile(wacz_filename):
        raise ValueError("No such file: %s" % wacz_filename)

    # List input data
    ext_path = 'EXTENSIONS/web1'
    ext_dir = ext_path + '/'
    members = []
    found_web = False
    for member in input_tar.getmembers():
        if member.name.startswith(ext_dir) or member.name == ext_path:
            found_web |= 1
        elif member.name.startswith('EXTENSIONS/web'):
            found_web |= 2
        else:
            members.append(member)

    if found_web & 2:
        logger.warning(
            "Replacing UNKNOWN web extension version from input RPZ",
        )
    elif found_web:
        logger.warning("Replacing existing web extension from input RPZ")

    with contextlib.ExitStack() as context:
        if found_web:
            # Create new tar
            output_tar = context.enter_context(
                tarfile.open(output_filename, 'w:'),
            )

            # Copy input data
            for member in members:
                output_tar.addfile(member, input_tar.extractfile(member))
        else:
            # Copy file
            with open(output_filename, 'wb') as output:
                pos = input_tar.fileobj.tell()
                input_tar.fileobj.seek(0, 0)
                try:
                    shutil.copyfileobj(input_tar.fileobj, output)
                finally:
                    input_tar.fileobj.seek(pos, 0)

            # Append to tar
            output_tar = context.enter_context(
                tarfile.open(output_filename, 'a:'),
            )

        # Add WACZ
        member = tarfile.TarInfo('EXTENSIONS/web1/archive.wacz')
        member.size = os.path.getsize(wacz_filename)
        st = os.stat(wacz_filename)
        member.mtime = st.st_mtime
        with open(wacz_filename, 'rb') as wacz:
            output_tar.addfile(member, wacz)


def combine_zip(input_zip, wacz_filename, output_filename):
    if not os.path.isfile(wacz_filename):
        raise ValueError("No such file: %s" % wacz_filename)

    # List input data
    ext_path = 'EXTENSIONS/web1'
    ext_dir = ext_path + '/'
    members = []
    found_web = False
    for member in input_zip.infolist():
        if member.filename.startswith(ext_dir) or member.filename == ext_path:
            found_web |= 1
        elif member.filename.startswith('EXTENSIONS/web'):
            found_web |= 2
        else:
            members.append(member)

    if found_web & 2:
        logger.warning(
            "Replacing UNKNOWN web extension version from input RPZ",
        )
    elif found_web:
        logger.warning("Replacing existing web extension from input RPZ")

    with contextlib.ExitStack() as context:
        if found_web:
            # Create new zip
            output_zip = context.enter_context(
                zipfile.ZipFile(output_filename, 'w'),
            )

            # Copy input data
            for member in members:
                with input_zip.open(member, 'r') as src:
                    with output_zip.open(member, 'w') as dest:
                        shutil.copyfileobj(src, dest)
        else:
            # Copy file
            with open(output_filename, 'wb') as output:
                pos = input_zip.fp.tell()
                input_zip.fp.seek(0, 0)
                try:
                    shutil.copyfileobj(input_zip.fp, output)
                finally:
                    input_zip.fp.seek(pos, 0)

            # Append to tar
            output_zip = context.enter_context(
                zipfile.ZipFile(output_filename, 'a'),
            )

        # Add WACZ
        st = os.stat(wacz_filename)
        mtime = time.localtime(st.st_mtime)
        member = zipfile.ZipInfo('EXTENSIONS/web1/archive.wacz', mtime[0:6])
        member.file_size = os.path.getsize(wacz_filename)
        with open(wacz_filename, 'rb') as src:
            with output_zip.open(member, 'w') as dest:
                shutil.copyfileobj(src, dest)


def combine(input_rpz, input_wacz, output_rpz):
    try:
        tar = tarfile.open(input_rpz)
    except tarfile.TarError:
        pass
    else:
        combine_tar(tar, input_wacz, output_rpz)
        tar.close()
        return

    try:
        zip = zipfile.ZipFile(input_rpz)
    except zipfile.BadZipfile:
        pass
    else:
        combine_zip(zip, input_wacz, output_rpz)
        zip.close()
        return

    raise ValueError("Input is not a TAR or a ZIP")
