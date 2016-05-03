#!/bin/bash

#First argument is taken as CMAKE_INSTALL_FULL_BINDIR
#Second argument is taken as CMAKE_INSTALL_FULL_LIBDIR

MOUNTPOINT=$HOME/Dropbox/
ENCRYPTED_DIRECTORY=$HOME/.ecs/encrypted/
DECRYPTED_DIRECTORY=$HOME/.ecs/decrypted/
CMAKE_INSTALL_FULL_BINDIR=$1
CMAKE_INSTALL_FULL_LIBDIR=$2

#Configure Makefile
printf "Configuring Makefile ... "
sed -i '/MOUNTPOINT=/c\MOUNTPOINT='$MOUNTPOINT Makefile
sed -i '/ENCRYPTED_DIRECTORY_ENCFS=/c\ENCRYPTED_DIRECTORY_ENCFS='$ENCRYPTED_DIRECTORY Makefile
sed -i '/DECRYPTED_DIRECTORY_ENCFS=/c\DECRYPTED_DIRECTORY_ENCFS='$DECRYPTED_DIRECTORY Makefile
printf "done.\n"

#Configure start_fuseecs.sh
printf "Configuring start_fuseecs.sh ... "
sed -i '/MOUNTPOINT=/c\MOUNTPOINT='$MOUNTPOINT start_fuseecs.sh
sed -i '/ENCRYPTED_DIRECTORY_ENCFS=/c\ENCRYPTED_DIRECTORY_ENCFS='$ENCRYPTED_DIRECTORY start_fuseecs.sh
sed -i '/DECRYPTED_DIRECTORY_ENCFS=/c\DECRYPTED_DIRECTORY_ENCFS='$DECRYPTED_DIRECTORY start_fuseecs.sh
sed -i '/CMAKE_INSTALL_FULL_BINDIR=/c\CMAKE_INSTALL_FULL_BINDIR='$CMAKE_INSTALL_FULL_BINDIR start_fuseecs.sh
sed -i '/CMAKE_INSTALL_FULL_LIBDIR=/c\CMAKE_INSTALL_FULL_LIBDIR='$CMAKE_INSTALL_FULL_LIBDIR start_fuseecs.sh
printf "done.\n"

#Configure start_share_a_folder.sh
printf "Configuring start_fuseecs.sh ... "
sed -i '/CMAKE_INSTALL_FULL_BINDIR=/c\CMAKE_INSTALL_FULL_BINDIR='$CMAKE_INSTALL_FULL_BINDIR ../share_a_folder/start_share_a_folder.sh
sed -i '/CMAKE_INSTALL_FULL_LIBDIR=/c\CMAKE_INSTALL_FULL_LIBDIR='$CMAKE_INSTALL_FULL_LIBDIR ../share_a_folder/start_share_a_folder.sh
printf "done.\n"

#Configure configuration.h
printf "Configuring configuration.h ...\n"
sed -i '/#define ACCESS_USER_ID /c\#define ACCESS_USER_ID '`echo $UID` configuration.h
sed -i '/#define MOUNTPOINT_DIRECTORY \"\"/c\#define MOUNTPOINT_DIRECTORY \"'$MOUNTPOINT'\"' configuration.h
sed -i '/#define ROOT_DIRECTORY \"\"/c\#define ROOT_DIRECTORY \"'$ENCRYPTED_DIRECTORY'\"' configuration.h
sed -i '/#define DECRYPTED_DIRECTORY \"\"/c\#define DECRYPTED_DIRECTORY \"'$DECRYPTED_DIRECTORY'\"' configuration.h
printf "Listing keys:\n"
gpg2 --list-secret-keys
read -p "Please copy and paste your key's fingerprint: " GPG_KEY_FINGERPRINT
sed -i '/#define OWN_PUBLIC_KEY_FINGERPRINT \"\"/c\#define OWN_PUBLIC_KEY_FINGERPRINT \"'$GPG_KEY_FINGERPRINT'\"' configuration.h
printf "Configuring configuration.h done.\n"

printf "Configuring direct_asymmetric_encryption/configuration.h ... "
sed -i '/#define CMAKE_INSTALL_FULL_BINDIR \"\"/c\#define CMAKE_INSTALL_FULL_BINDIR \"'$CMAKE_INSTALL_FULL_BINDIR'\"' direct_asymmetric_encryption/configuration.h
printf "done.\n"
