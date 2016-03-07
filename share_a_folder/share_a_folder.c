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
	char *decrypted_folder = argv[1];
	char *fingerprint = argv[2];
	
	gpgme_check_version(NULL);
	char *encrypted_folder = NULL;
	{
		GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(decrypted_folder, result)
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, encrypted_folder)
	}

	STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_folder, encrypted_folder_name)
	//Share password file
	{
		//Read password
		LOCAL_STR_CAT(encrypted_folder, PASSWORD_FILE_NAME, path_to_password_file)
		READ_FILE(path_to_password_file, password)
		//Encrypt password with chosen public key
		SEPARATE_STRINGS(encrypted_folder_name, password, path_with_password)
		sign_and_encrypt(path_with_password, fingerprint, encrypted_folder, PASSWORD_FILE_NAME);
	}

	//Share encfs configuration file
	{
		//Read encfs configuration file
		LOCAL_STR_CAT(encrypted_folder, ENCFS_CONFIGURATION_FILE, path_to_encfs_configuration_file)
		READ_FILE(path_to_encfs_configuration_file, encfs_configuration_data)
		//Encrypt encfs configuration file with chosen public key
		SEPARATE_STRINGS(encrypted_folder_name, encfs_configuration_data, path_with_encfs_configuration_data)
		sign_and_encrypt(path_with_encfs_configuration_data, fingerprint, encrypted_folder, ENCFS_CONFIGURATION_FILE);
	}

	//Share folder name
	{
		STRIP_UPPER_DIRECTORIES_AND_SLASH(decrypted_folder, plain_folder_name_maybe_with_ending_slash)
		REMOVE_SLASH_IF_NECESSARY_REPEATABLE(plain_folder_name_maybe_with_ending_slash, plain_folder_name)
		free(plain_folder_name_maybe_with_ending_slash);
		SEPARATE_STRINGS(encrypted_folder_name, plain_folder_name, encrypted_and_decrypted_folder_name)
		free(plain_folder_name);
		sign_and_encrypt(encrypted_and_decrypted_folder_name, fingerprint, encrypted_folder, DECRYPTED_FOLDER_NAME_FILE_NAME);
	}

	//If encrypted_folder starts with the root directory, do not show the root directory to the user
	char *encrypted_folder_to_show_to_user;
	if(strncmp(ROOT_DIRECTORY, encrypted_folder, strlen(ROOT_DIRECTORY)) == 0){
		encrypted_folder_to_show_to_user = encrypted_folder + strlen(ROOT_DIRECTORY);
	} else {
		encrypted_folder_to_show_to_user = encrypted_folder;
	}
	
	printf("Enabled decryption of folder %s for key with fingerprint %s. Please share the following folder in your Dropbox: %s\n", decrypted_folder, fingerprint, encrypted_folder_to_show_to_user);

	free(encrypted_folder);
	return 0;
}
