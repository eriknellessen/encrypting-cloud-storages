#!/bin/bash

MOUNTPOINT=$HOME/Dropbox/
ENCRYPTED_DIRECTORY=$HOME/.ecs/encrypted/
DECRYPTED_DIRECTORY=$HOME/.ecs/decrypted/

#Configure Makefile
printf "Configuring Makefile ... "
sed -i '/MOUNTPOINT=/c\MOUNTPOINT='$MOUNTPOINT Makefile
sed -i '/ENCRYPTED_DIRECTORY_ENCFS=/c\ENCRYPTED_DIRECTORY_ENCFS='$ENCRYPTED_DIRECTORY Makefile
sed -i '/DECRYPTED_DIRECTORY_ENCFS=/c\DECRYPTED_DIRECTORY_ENCFS='$DECRYPTED_DIRECTORY Makefile
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