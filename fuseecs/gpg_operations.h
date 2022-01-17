#ifndef GPG_OPERATIONS_H
#define GPG_OPERATIONS_H

#include <gpgme.h>
#include <unistd.h>
#include "data_operations.h"

#include "direct_asymmetric_decryption_on_token/access_token.h"

#define ENCRYPT 0
#define DECRYPT 1

#define DECRYPT_ON_TOKEN(PATH, RESULT) /*Get cipher text from file */\
	/* Debug */\
	printf("DECRYPT_ON_TOKEN start.\n");\
	/* File might contain zeros, so we need the length. It is saved in the 'pos' variable. */\
	READ_FILE(PATH, file_content)\
	\
	/* We are decrypting a password here. So we need to strip the path, send it to the\
	* token, then send the cipher text. */\
	/* Strip the path */\
	UNSEPARATE_STRINGS(file_content, pos, meta_data, cipher_text, cipher_text_length_including_trailing_zero)\
	/* Decrypt */\
	if(send_meta_data_to_token(meta_data, strlen(meta_data)) != 0){\
		fprintf(stderr, "Could not send meta data to token.\n");\
		exit(-1);\
	}\
	char *plain_text;\
	while(rsa_decrypt_on_token(cipher_text, cipher_text_length_including_trailing_zero - 1, &plain_text) != 0);\
	\
	/* Copy result to the local variable. Skip the hash value. */\
	char RESULT[strlen(plain_text + get_hash_length()) + 1];\
	strcpy(RESULT, plain_text + get_hash_length());\
	free(plain_text);\
	/* Debug */\
	printf("DECRYPT_ON_TOKEN end.\n");

#define VERIFY_PATH(DATA, PATH, RESULT) UNSEPARATE_STRINGS(DATA, strlen(DATA), path, RESULT, result_length)\
	if(strcmp(path, PATH)){\
		fprintf(stderr, "Data for path %s in path %s.\n", PATH, path);\
		exit(-1);\
	}\

/* TODO: Also check signature. Anyhow, in this scenario, the authenticity is not so important anyhow, as we do not trust our system anymore.
 * But anyhow, we do not need to allow this attack.
 */
#define DECRYPT_DATA_ON_TOKEN_AND_VERIFY_PATH(PATH_TO_DIRECTORY, PATH_TO_VERIFY, FILE_NAME, RESULT) LOCAL_STR_CAT(PATH_TO_DIRECTORY, FILE_NAME, path_without_file_ending)\
	LOCAL_STR_CAT(path_without_file_ending, ENCRYPTED_FILE_ENDING, path_with_file_ending)\
	DECRYPT_ON_TOKEN(path_with_file_ending, RESULT)\
	/* This is no more needed, as the user verified the path. */\
	/*VERIFY_PATH(path_and_data, PATH_TO_VERIFY, RESULT)*/

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
		LOCAL_STR_CAT(path_with_password_prefix_and_fingerprint, ENCRYPTED_FILE_ENDING, path_with_encrypted_password_file)\
		LOCAL_STR_CAT(path_with_slash_at_the_end, PASSWORD_FILE_NAME, path_with_password_file)\
		if(access(path_with_password_file, F_OK) == 0){\
			READ_FILE(path_with_password_file, result)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, RESULT)\
		} else if(access(path_with_encrypted_password_file, F_OK) == 0){\
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
	RESULT[PASSWORD_LENGTH] = 0;

void sign(const char *data, const char *path, const char *file_name);
char *verify_signature_and_path(const char *path, const char *path_to_compare_to, const char *file_name);
void direct_rsa_encrypt_and_save_to_file(const char *plain_text, int plain_text_length, const char *public_key_fingerprint, const char *path, const char *file_name);
char *compute_hash_value_from_meta_data(const char *meta_data, int meta_data_length, int *hash_value_length);
int directory_contains_authentic_file(char *encrypted_directory, char *file_name);
int get_hash_length();

#endif
