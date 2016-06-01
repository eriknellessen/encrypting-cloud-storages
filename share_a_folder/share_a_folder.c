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

	STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(decrypted_folder, meta_data)
	//Share password file
	{
		//Read password
		LOCAL_STR_CAT(encrypted_folder, PASSWORD_FILE_NAME, path_to_password_file)
		READ_FILE(path_to_password_file, password)
		int hash_value_length;
		char *hash_value_of_meta_data = compute_hash_value_from_meta_data(meta_data, strlen(meta_data), &hash_value_length);
		char plain_text[hash_value_length + strlen(password) + 1];
		memcpy(plain_text, hash_value_of_meta_data, hash_value_length);
		free(hash_value_of_meta_data);
		strcpy(plain_text + hash_value_length, password);
		direct_rsa_encrypt_and_save_to_file(plain_text, hash_value_length + strlen(password), fingerprint, encrypted_folder, PASSWORD_FILE_NAME);
		//Add meta data to the beginning of the file
		//Concatenate path
		LOCAL_STR_CAT(encrypted_folder, PASSWORD_FILE_NAME, path_with_file_name)
		LOCAL_STR_CAT(path_with_file_name, fingerprint, path_with_file_name_and_public_key_fingerprint)
		LOCAL_STR_CAT(path_with_file_name_and_public_key_fingerprint, ENCRYPTED_FILE_ENDING, concatenated_path)
		long cipher_text_length;
		char *meta_data_and_cipher_text = NULL;
		{
			READ_FILE(concatenated_path, cipher_text)
			//pos contains length of read cipher_text, (see macro READ_FILE)
			cipher_text_length = pos;
			//SEPARATE_STRINGS does not work here, as the cipher text might contain zeros.
			//SEPARATE_STRINGS(decrypted_directory, cipher_text, meta_data_and_cipher_text_local)
			meta_data_and_cipher_text = malloc(strlen(meta_data) + 1 + cipher_text_length);
			memcpy(meta_data_and_cipher_text, meta_data, strlen(meta_data));
			meta_data_and_cipher_text[strlen(meta_data)] = PATH_SEPARATOR;
			memcpy(meta_data_and_cipher_text + strlen(meta_data) + 1, cipher_text, cipher_text_length);
		}
		WRITE_BINARY_DATA_TO_FILE(concatenated_path, meta_data_and_cipher_text, strlen(meta_data) + 1 + cipher_text_length)
		free(meta_data_and_cipher_text);
	}

	//We do not encrypt the encfs configuration file anymore, so we have only one decryption for each folder.

	//Share folder name
	{
		STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_folder, encrypted_folder_name)
		SEPARATE_STRINGS(encrypted_folder_name, meta_data, encrypted_and_decrypted_folder_name)
		sign(encrypted_and_decrypted_folder_name, encrypted_folder, DECRYPTED_FOLDER_NAME_FILE_NAME);
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
