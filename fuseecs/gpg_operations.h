#ifndef GPG_OPERATIONS_H
#define GPG_OPERATIONS_H

#include <gpgme.h>
#include "data_operations.h"

#define ENCRYPT 0
#define DECRYPT 1

//TODO: Check, if the signature has been made with the expected key.
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
		fprintf(stderr, "Could not read encrypted data from file %s.\n", PATH);\
		exit(-1);\
	}\
	if(gpgme_op_decrypt_verify(gpgme_ctx, gpgme_encrypted_data, gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\
		fprintf(stderr, "Could not decrypt and verify file %s.\n", PATH);\
		exit(-1);\
	}\
	gpgme_data_release(gpgme_encrypted_data);\
	gpgme_release(gpgme_ctx);\
	\
	plain_text = gpgme_data_release_and_get_mem(gpgme_decrypted_data, &length);\
}\
char RESULT[length];\
if(memcpy(RESULT, plain_text, length) != RESULT){\
	fprintf(stderr, "Could not copy decrypted data.\n");\
	exit(-1);\
}\
RESULT[length - 1] = 0;\
gpgme_free(plain_text);

#define DECRYPT_DATA_AND_VERIFY_PATH(PATH, FILE_NAME, RESULT) size_t password_length;\
size_t end_of_path;\
LOCAL_STR_CAT(PATH, FILE_NAME, path_without_file_ending)\
LOCAL_STR_CAT(path_without_file_ending, ENCRYPTED_FILE_ENDING, path_with_file_ending)\
DECRYPT_AND_VERIFY(path_with_file_ending, path_and_password)\
{\
char *end_of_path_string = strchr(path_and_password, PATH_SEPARATOR);\
end_of_path = end_of_path_string - path_and_password;\
char path[end_of_path + 1];\
strncpy(path, path_and_password, end_of_path);\
path[end_of_path] = 0;\
if(strcmp(path, PATH)){\
	fprintf(stderr, "Password for path %s in path %s.\n", PATH, path);\
	exit(-1);\
}\
password_length = strlen(path_and_password - (end_of_path + 1));\
}\
char RESULT[password_length + 1];\
strcpy(RESULT, path_and_password + end_of_path + 1);

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
	/* Debug */ \
	printf("relative_path: %s\n", relative_path);\
	/* Get folder names */ \
	char *next_folder = strtok(relative_path, "/");\
	LOCAL_STR_CAT(PASSWORD_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, password_file)\
	while(next_folder != NULL){\
		printf("current_root_directory: %s\n", current_root_directory);\
		printf("current_decrypted_path: %s\n", current_decrypted_path);\
		printf("next_folder: %s\n", next_folder);\
		char *current_transformed_folder_name = NULL;\
		/* Get password from current root directory */ \
		DECRYPT_DATA_AND_VERIFY_PATH(current_root_directory, password_file, password)\
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
		if(MODE == ENCRYPT){\
			LOCAL_STR_CAT(current_root_directory, current_transformed_folder_name, result)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, next_root_directory_without_slash)\
		} else {\
			LOCAL_STR_CAT(current_root_directory, next_folder, result)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, next_root_directory_without_slash)\
			LOCAL_STR_CAT(current_decrypted_path, current_transformed_folder_name, grown_decrypted_path_without_slash)\
			APPEND_SLASH_IF_NECESSARY(grown_decrypted_path_without_slash, grown_decrypted_path)\
			PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(grown_decrypted_path, current_decrypted_path)\
		}\
		free(current_transformed_folder_name);\
		APPEND_SLASH_IF_NECESSARY(next_root_directory_without_slash, next_root_directory)\
		free(next_root_directory_without_slash);\
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(next_root_directory, current_root_directory)\
		next_folder = strtok(NULL, "/");\
	}\
}\
printf("current_root_directory: %s\n", current_root_directory);\
printf("current_decrypted_path: %s\n", current_decrypted_path);\
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
RUN_COMMAND_AND_GET_OUTPUT(cmd, RESULT)

void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name);

#endif