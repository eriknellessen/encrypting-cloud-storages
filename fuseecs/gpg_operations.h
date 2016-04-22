#ifndef GPG_OPERATIONS_H
#define GPG_OPERATIONS_H

#include <gpgme.h>
#include <unistd.h>
#include "data_operations.h"

#include "direct_asymmetric_decryption_on_token/access_token.h"

#define ENCRYPT 0
#define DECRYPT 1

/* TODO: Check, if the signature has been made with the expected key. If we do not check this, the cloud storage
 * provider could place the data signed with any trusted key in our key ring in our cloud storage folder.
 */
#define DECRYPT_AND_VERIFY(PATH, RESULT) char *plain_text;\
	size_t length;\
	{\
		gpgme_ctx_t gpgme_ctx;\
		if(gpgme_new(&gpgme_ctx) != GPG_ERR_NO_ERROR){\
			fprintf(stderr, "Could not create gpg context.\n");\
			exit(-1);\
		}\
		gpgme_data_t gpgme_encrypted_data;\
		if(gpgme_data_new_from_file(&gpgme_encrypted_data, PATH, 1) != GPG_ERR_NO_ERROR){\
			fprintf(stderr, "Could not read encrypted data from file %s.\n", PATH);\
			exit(-1);\
		}\
		gpgme_data_t gpgme_decrypted_data;\
		if(gpgme_data_new(&gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\
			fprintf(stderr, "Could not create GPGME data handle for decrypted data.\n");\
			exit(-1);\
		}\
		/* TODO: Find out, why gpgme gets stuck when signing with a token. For now, we are skipping the verifying. */\
		/*if(gpgme_op_decrypt_verify(gpgme_ctx, gpgme_encrypted_data, gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\*/\
		if(gpgme_op_decrypt(gpgme_ctx, gpgme_encrypted_data, gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\
			fprintf(stderr, "Could not decrypt and verify file %s.\n", PATH);\
			exit(-1);\
		}\
		gpgme_data_release(gpgme_encrypted_data);\
		gpgme_release(gpgme_ctx);\
		\
		plain_text = gpgme_data_release_and_get_mem(gpgme_decrypted_data, &length);\
	}\
	/* Reserve one additional byte for the ending 0 byte */\
	char RESULT[length + 1];\
	if(memcpy(RESULT, plain_text, length) != RESULT){\
		fprintf(stderr, "Could not copy decrypted data.\n");\
		exit(-1);\
	}\
	RESULT[length] = 0;\
	gpgme_free(plain_text);

#define DECRYPT_ON_TOKEN(PATH, RESULT) /*Get cipher text from file */\
	/* File might contain zeros, so we need the length. It is saved in the 'pos' variable. */\
	READ_FILE(PATH, cipher_text)\
	\
	/* Decrypt */\
	char *plain_text;\
	while(rsa_decrypt_on_token(cipher_text, pos, &plain_text) != 0);\
	\
	/* Copy result to the local variable. */\
	char RESULT[strlen(plain_text) + 1];\
	strcpy(RESULT, plain_text);\
	free(plain_text);\

#define VERIFY_PATH(DATA, PATH, RESULT) size_t data_length;\
	size_t end_of_path;\
	{\
		char *end_of_path_string = strchr(DATA, PATH_SEPARATOR);\
		end_of_path = end_of_path_string - DATA;\
		char path[end_of_path + 1];\
		strncpy(path, DATA, end_of_path);\
		path[end_of_path] = 0;\
		if(strcmp(path, PATH)){\
			fprintf(stderr, "Data for path %s in path %s.\n", PATH, path);\
			exit(-1);\
		}\
		data_length = strlen(DATA - (end_of_path + 1));\
	}\
	char RESULT[data_length + 1];\
	strcpy(RESULT, DATA + end_of_path + 1);

#define DECRYPT_DATA_AND_VERIFY_PATH(PATH_TO_DIRECTORY, PATH_TO_VERIFY, FILE_NAME, RESULT) LOCAL_STR_CAT(PATH_TO_DIRECTORY, FILE_NAME, path_without_file_ending)\
	LOCAL_STR_CAT(path_without_file_ending, ENCRYPTED_FILE_ENDING, path_with_file_ending)\
	DECRYPT_AND_VERIFY(path_with_file_ending, path_and_data)\
	VERIFY_PATH(path_and_data, PATH_TO_VERIFY, RESULT)

#define DECRYPT_DATA_ON_TOKEN_AND_VERIFY_PATH(PATH_TO_DIRECTORY, PATH_TO_VERIFY, FILE_NAME, RESULT) LOCAL_STR_CAT(PATH_TO_DIRECTORY, FILE_NAME, path_without_file_ending)\
	LOCAL_STR_CAT(path_without_file_ending, ENCRYPTED_FILE_ENDING, path_with_file_ending)\
	/*DECRYPT_AND_VERIFY(path_with_file_ending, path_and_data)*/\
	DECRYPT_ON_TOKEN(path_with_file_ending, path_and_data)\
	VERIFY_PATH(path_and_data, PATH_TO_VERIFY, RESULT)

#define SET_PATH_TO_COMPARE_TO(PATH, RESULT)char *RESULT = NULL;\
	STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(PATH, directory_name)\
	if(directory_contains_authentic_file(PATH, DECRYPTED_FOLDER_NAME_FILE_NAME)){\
		RESULT = directory_name;\
	} else {\
		RESULT = PATH;\
	}

#define GET_PASSWORD(PATH, RESULT) GET_FOLDER_NAME_ITERATIVELY(PATH, DECRYPT, decrypted_path)\
	GET_PASSWORD_WITH_KNOWN_DECRYPTED_DIRECTORY(PATH, decrypted_path, RESULT)

#define GET_PASSWORD_WITH_KNOWN_DECRYPTED_DIRECTORY(PATH, DECRYPTED_PATH, RESULT) char *RESULT = NULL;\
	{\
		LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)\
		APPEND_SLASH_IF_NECESSARY(PATH, path_with_slash_at_the_end)\
		LOCAL_STR_CAT(path_with_slash_at_the_end, password_file, path_with_password_prefix_and_fingerprint)\
		LOCAL_STR_CAT(path_with_password_prefix_and_fingerprint, ENCRYPTED_FILE_ENDING, path_with_password_file)\
		if(access(path_with_password_file, F_OK) == 0){\
			SET_PATH_TO_COMPARE_TO(PATH, path_to_compare_to)\
			/*DECRYPT_DATA_AND_VERIFY_PATH(PATH, path_to_compare_to, password_file, result)*/\
			DECRYPT_DATA_ON_TOKEN_AND_VERIFY_PATH(PATH, path_to_compare_to, password_file, result)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, RESULT)\
		} else {\
			LOCAL_STR_CAT(DECRYPTED_PATH, "../", one_folder_above_decrypted_path)\
			STRIP_UPPER_DIRECTORIES_AND_SLASH(PATH, stripped_path)\
			LOCAL_STR_CAT(PASSWORD_FILE_NAME, stripped_path, password_file_with_stripped_path)\
			free(stripped_path);\
			LOCAL_STR_CAT(one_folder_above_decrypted_path, password_file_with_stripped_path, password_path)\
			READ_FILE(password_path, path_with_password)\
			VERIFY_PATH(path_with_password, PATH, result)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, RESULT)\
		}\
	}

//encfsctl decode --extpass="echo password" ROOT_DIRECTORY DIRECTORY
#define GET_DECRYPTED_FOLDER_NAME(UPPER_DIRECTORY, DIRECTORY, PASSWORD, RESULT) LOCAL_STR_CAT("encfsctl decode --extpass=\"echo ", PASSWORD, cmd_with_password)\
	LOCAL_STR_CAT(cmd_with_password, "\" ", cmd_with_password_and_ending_quotation_mark)\
	LOCAL_STR_CAT(cmd_with_password_and_ending_quotation_mark, UPPER_DIRECTORY, cmd_with_root_directory)\
	LOCAL_STR_CAT(cmd_with_root_directory, " ", cmd_with_root_directory_and_space)\
	LOCAL_STR_CAT(cmd_with_root_directory_and_space, DIRECTORY, cmd)\
	RUN_COMMAND_AND_GET_OUTPUT(cmd, RESULT)

//encfsctl decode --extpass="echo password" ROOT_DIRECTORY DIRECTORY
#define GET_ENCRYPTED_FOLDER_NAME(UPPER_DIRECTORY, DIRECTORY, PASSWORD, RESULT) LOCAL_STR_CAT("encfsctl encode --extpass=\"echo ", PASSWORD, cmd_with_password)\
	LOCAL_STR_CAT(cmd_with_password, "\" ", cmd_with_password_and_ending_quotation_mark)\
	LOCAL_STR_CAT(cmd_with_password_and_ending_quotation_mark, UPPER_DIRECTORY, cmd_with_root_directory)\
	LOCAL_STR_CAT(cmd_with_root_directory, " ", cmd_with_root_directory_and_space)\
	LOCAL_STR_CAT(cmd_with_root_directory_and_space, DIRECTORY, cmd)\
	RUN_COMMAND_AND_GET_OUTPUT(cmd, RESULT)

#define GET_FOLDER_NAME_ITERATIVELY(DIRECTORY, MODE, RESULT) char *current_root_directory = NULL;\
	char *current_decrypted_path = NULL;\
	{\
		char root_directory[] = ROOT_DIRECTORY;\
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(root_directory, current_root_directory)\
		char decrypted_directory[] = DECRYPTED_DIRECTORY;\
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(decrypted_directory, current_decrypted_path)\
		const char *const_relative_path;\
		/* Remove ROOT_DIRECTORY */ \
		if(strstr(DIRECTORY, MOUNTPOINT_DIRECTORY) == DIRECTORY){\
			const_relative_path = DIRECTORY + sizeof(char) * strlen(MOUNTPOINT_DIRECTORY);\
		} else if(strstr(DIRECTORY, DECRYPTED_DIRECTORY) == DIRECTORY){\
			const_relative_path = DIRECTORY + sizeof(char) * strlen(DECRYPTED_DIRECTORY);\
		} else if(strstr(DIRECTORY, ROOT_DIRECTORY) == DIRECTORY){\
			const_relative_path = DIRECTORY + sizeof(char) * strlen(ROOT_DIRECTORY);\
		} else{\
			const_relative_path = DIRECTORY;\
		}\
		char relative_path[strlen(const_relative_path) + 1];\
		strcpy(relative_path, const_relative_path);\
		/* Get folder names */ \
		char *end_string;\
		char *next_folder = strtok_r(relative_path, "/", &end_string);\
		LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)\
		while(next_folder != NULL){\
			char *current_transformed_folder_name = NULL;\
			/* Get password from current root directory */ \
			GET_PASSWORD_WITH_KNOWN_DECRYPTED_DIRECTORY(current_root_directory, current_decrypted_path, password)\
			/* Get encoded name of next folder */ \
			if(MODE == ENCRYPT){\
				GET_ENCRYPTED_FOLDER_NAME(current_root_directory, next_folder, password, encoded_folder_name)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(encoded_folder_name, current_transformed_folder_name)\
			} else {\
				GET_DECRYPTED_FOLDER_NAME(current_root_directory, next_folder, password, decoded_folder_name)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(decoded_folder_name, current_transformed_folder_name)\
			}\
			/* Set the encoded name of the next folder as next root directory */ \
			char *next_root_directory_without_slash = NULL;\
			char *next_decrypted_path_without_slash = NULL;\
			if(MODE == ENCRYPT){\
				LOCAL_STR_CAT(current_decrypted_path, next_folder, grown_decrypted_path_without_slash)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(grown_decrypted_path_without_slash, next_decrypted_path_without_slash)\
				LOCAL_STR_CAT(current_root_directory, current_transformed_folder_name, result)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, next_root_directory_without_slash)\
			} else {\
				LOCAL_STR_CAT(current_root_directory, next_folder, result)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, next_root_directory_without_slash)\
				LOCAL_STR_CAT(current_decrypted_path, current_transformed_folder_name, grown_decrypted_path_without_slash)\
				PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(grown_decrypted_path_without_slash, next_decrypted_path_without_slash)\
			}\
			free(current_transformed_folder_name);\
			\
			APPEND_SLASH_IF_NECESSARY_REPEATABLE(next_root_directory_without_slash, next_root_directory)\
			free(next_root_directory_without_slash);\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(next_root_directory, current_root_directory)\
			free(next_root_directory);\
			\
			APPEND_SLASH_IF_NECESSARY_REPEATABLE(next_decrypted_path_without_slash, next_decrypted_path)\
			free(next_decrypted_path_without_slash);\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(next_decrypted_path, current_decrypted_path)\
			free(next_decrypted_path);\
			\
			next_folder = strtok_r(NULL, "/", &end_string);\
		}\
	}\
	int length;\
	char *string_to_copy_from;\
	if(MODE == ENCRYPT){\
		length = strlen(current_root_directory) + 1;\
		string_to_copy_from = current_root_directory;\
	} else {\
		length = strlen(current_decrypted_path) + 1;\
		string_to_copy_from = current_decrypted_path;\
	}\
	char RESULT[length];\
	strcpy(RESULT, string_to_copy_from);\
	free(current_root_directory);\
	free(current_decrypted_path);

#define GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(DIRECTORY, RESULT) GET_FOLDER_NAME_ITERATIVELY(DIRECTORY, ENCRYPT, RESULT)
#define GET_DECRYPTED_FOLDER_NAME_ITERATIVELY(DIRECTORY, RESULT) GET_FOLDER_NAME_ITERATIVELY(DIRECTORY, DECRYPT, RESULT)

#define GET_RANDOM_PASSWORD(RESULT) LOCAL_STR_CAT(MAKEPASSWD_COMMAND, PASSWORD_LENGTH_STRING, cmd)\
	RUN_COMMAND_AND_GET_OUTPUT(cmd, RESULT)\
	RESULT[PASSWORD_LENGTH] = 0;\
	/* Debug */\
	printf("Got the following random password: %s\n", RESULT);

void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name);
void direct_rsa_encrypt_and_save_to_file(const char *plain_text, const char *public_key_fingerprint, const char *path, const char *file_name);
char *compute_hash_value_from_meta_data(const char *meta_data, int meta_data_length);
int directory_contains_authentic_file(char *encrypted_directory, char *file_name);

#endif