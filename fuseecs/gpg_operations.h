#ifndef GPG_OPERATIONS_H
#define GPG_OPERATIONS_H

#include <gpgme.h>
#include "data_operations.h"

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

#define GET_DECRYPTED_FOLDER_NAME(DIRECTORY) encfsctl decode --extpass="echo password" DIRECTORY

#define GET_RANDOM_PASSWORD(RESULT) char *get_random_password_data = NULL;\
{\
	LOCAL_STR_CAT(MAKEPASSWD_COMMAND, PASSWORD_LENGTH_STRING, cmd)\
	FILE *pipe = popen(cmd, "r");\
	\
	char buffer[BUFFER_SIZE];\
	int size;\
	int pos = 0;\
	\
	if(pipe) {\
		while(fgets(buffer, BUFFER_SIZE, pipe) != NULL) {\
			size = strlen(buffer);\
			get_random_password_data = realloc(get_random_password_data, pos + size);\
			memcpy(&get_random_password_data[pos], buffer, size);\
			pos += size;\
		}\
	}\
	\
	if(pclose(pipe)){\
		fprintf(stderr, "Could not generate password.\n");\
		exit(-1);\
	}\
	\
}\
char RESULT[strlen(get_random_password_data)];\
memcpy(RESULT, get_random_password_data, strlen(get_random_password_data));\
RESULT[strlen(get_random_password_data) - 1] = 0;\
free(get_random_password_data);

void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name);

#endif