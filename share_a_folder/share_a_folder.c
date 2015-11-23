#include "../fuseecs/configuration.h"
#include "../fuseecs/gpg_operations.h"
#include <stdlib.h>

char usage_string[] = "Usage: share_a_folder FOLDER OPENPGP_FINGERPRINT\n"
"Always give the full path. All characters in the fingerprint must be uppercase.\n";

/*
 * Input: A folder and a fingerprint of an OpenPGP key
 */
int main(int argc, char *argv[])
{
	if(argc != 3){
		fprintf(stderr, usage_string);\
		exit(-1);\
	}
	char *folder = argv[1];
	char *fingerprint = argv[2];
	
	gpgme_check_version(NULL);
	//Decrypt password
	LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)
	DECRYPT_DATA_AND_VERIFY_PATH(folder, password_file, password)
	//Encrypt password with chosen public key
	SEPARATE_STRINGS(folder, password, path_with_password)
	sign_and_encrypt(path_with_password, fingerprint, folder, PASSWORD_FILE_NAME);
	return 0;
}
