#!/bin/bash

#These values are filled in by configuration.sh
CMAKE_INSTALL_FULL_BINDIR=
CMAKE_INSTALL_FULL_LIBDIR=

if [ $# -lt 2 ]
then
	echo "Usage: $0 FOLDER OPENPGP_FINGERPRINT"
	echo "Always give the full path. All characters in the fingerprint must be uppercase."
	exit 1
fi

LD_LIBRARY_PATH=$CMAKE_INSTALL_FULL_LIBDIR:$LD_LIBRARY_PATH $CMAKE_INSTALL_FULL_BINDIR/share_a_folder $1 $2
