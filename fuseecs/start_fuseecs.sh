#!/bin/bash

#These values are filled in by configuration.sh
MOUNTPOINT=/home/erik/Dropbox/
ENCRYPTED_DIRECTORY_ENCFS=/home/erik/.ecs/encrypted/
DECRYPTED_DIRECTORY_ENCFS=/home/erik/.ecs/decrypted/
CMAKE_INSTALL_FULL_BINDIR=/home/erik/user-controlled-decryption-operations/encrypting-cloud-storages/build
CMAKE_INSTALL_FULL_LIBDIR=

mkdir -p $MOUNTPOINT $ENCRYPTED_DIRECTORY_ENCFS $DECRYPTED_DIRECTORY_ENCFS

LD_LIBRARY_PATH=$CMAKE_INSTALL_FULL_LIBDIR:$LD_LIBRARY_PATH $CMAKE_INSTALL_FULL_BINDIR/fuseecs -f -o allow_other $MOUNTPOINT
