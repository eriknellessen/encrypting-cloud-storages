#define BUFFER_SIZE 1024

#define ACCESS_USER_ID 1000
#define ROOT_USER_ID 0
//#define ENCFS_USER_ID 1001

#define ROOT_DIRECTORY "/tmp/encrypted/"
#define DECRYPTED_DIRECTORY "/tmp/decrypted/"
#define ENCFS_CONFIGURATION_FILE ".encfs6.xml"
#define ENCFS_COMMAND "encfs -o allow_other -v -d -s --stdinpass --standard "
#define GPG_SIGN_COMMAND "gpg2 --sign --local-user "
#define GPG_ENCRYPTION_OPTION " --encrypt -r "
#define GPG_OUTPUT_OPTION " --output "
#define SIGNED_FILE_ENDING ".sig"
#define ENCRYPTED_FILE_ENDING ".gpg"
#define PASSWORD_FILE_NAME ".password"

#define OWN_PUBLIC_KEY_FINGERPRINT "A6506F46"

#define MAKEPASSWD_COMMAND "makepasswd --chars "
#define PASSWORD_LENGTH_STRING "64"
