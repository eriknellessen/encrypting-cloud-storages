#include "../fuseecs/configuration.h"
#include "../fuseecs/gpg_operations.h"
#include <stdlib.h>

char usage_string[] = "Usage: share_a_folder FOLDER OPENPGP_FINGERPRINT\n"
"Always give the full path. All characters in the fingerprint must be uppercase.\n";

/*
 * Input: A folder and a fingerprint of an OpenPGP key
 */
//TODO: Let the user choose the decrypted folder name, not the encrypted one.
int main(int argc, char *argv[])
{
	if(argc != 3){
		fprintf(stderr, usage_string);\
		exit(-1);\
	}
	char *decrypted_folder = argv[1];
	char *fingerprint = argv[2];
	
	gpgme_check_version(NULL);
	GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(decrypted_folder, encrypted_folder)
	//Decrypt password
	LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)
	DECRYPT_DATA_AND_VERIFY_PATH(encrypted_folder, password_file, password)
	//Encrypt password with chosen public key
	SEPARATE_STRINGS(encrypted_folder, password, path_with_password)
	sign_and_encrypt(path_with_password, fingerprint, encrypted_folder, PASSWORD_FILE_NAME);
	return 0;
}
