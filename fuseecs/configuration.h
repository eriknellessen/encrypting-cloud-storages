#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#define BUFFER_SIZE 1024

#define ACCESS_USER_ID 1000
#define ROOT_USER_ID 0
//#define ENCFS_USER_ID 1001

#define ROOT_DIRECTORY "/home/destroyer/.ecs/encrypted/"
#define DECRYPTED_DIRECTORY "/home/destroyer/.ecs/decrypted/"
#define MOUNTPOINT_DIRECTORY "/home/destroyer/Dropbox/"
#define ENCFS_CONFIGURATION_FILE ".encfs6.xml"
#define ENCFS_COMMAND "encfs -o allow_other -v -d -s --standard --extpass=\""
#define GPG_SIGN_COMMAND "gpg2 --sign --local-user "
#define GPG_ENCRYPTION_OPTION " --encrypt -r "
#define GPG_OUTPUT_OPTION " --output "
#define SIGNED_FILE_ENDING ".sig"
#define ENCRYPTED_FILE_ENDING ".gpg"
#define PASSWORD_FILE_NAME ".password"
#define PATH_SEPARATOR 0x1F
#define PATH_SEPARATOR_STRING {0x1F, 0}

#define OWN_PUBLIC_KEY_FINGERPRINT "3BB86E8F"

#define MAKEPASSWD_COMMAND "makepasswd --chars "
#define PASSWORD_LENGTH_STRING "64"

#define CAT_COMMAND "cat "

#define DROPBOX_INTERNAL_FILES_DIRECTORY ".dropbox.cache"

#define DECRYPTED_FOLDER_NAME_FILE_NAME ".decrypted_folder_name"
#define DO_NOT_DECRYPT_THIS_DIRECTORY_FILE_NAME ".do_not_decrypt_this_directory"

#endif