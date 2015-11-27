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
	char *encrypted_folder = NULL;
	{
		GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(decrypted_folder, result)
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, encrypted_folder)
	}
	
	//Share password file
	{
		//Decrypt password
		LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_folder, password_file, password)
		//Encrypt password with chosen public key
		SEPARATE_STRINGS(encrypted_folder, password, path_with_password)
		sign_and_encrypt(path_with_password, fingerprint, encrypted_folder, PASSWORD_FILE_NAME);
	}
	
	//Share encfs configuration file
	{
		//Decrypt encfs configuration file
		LOCAL_STR_CAT(ENCFS_CONFIGURATION_FILE, OWN_PUBLIC_KEY_FINGERPRINT, encfs_configuration_file)
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_folder, encfs_configuration_file, encfs_configuration_data)
		//Encrypt password with chosen public key
		SEPARATE_STRINGS(encrypted_folder, encfs_configuration_data, path_with_encfs_configuration_data)
		sign_and_encrypt(path_with_encfs_configuration_data, fingerprint, encrypted_folder, ENCFS_CONFIGURATION_FILE);
	}
	
	free(encrypted_folder);
	return 0;
}
