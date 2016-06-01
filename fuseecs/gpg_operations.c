#include "gpg_operations.h"
#include <stdlib.h>
#include <stdio.h>

#include "direct_asymmetric_encryption/direct_rsa_encryption.h"

//We do not encrypt here, because we do not want to have two decryption operations to decrypt one folder
void sign(const char *data, const char *path, const char *file_name){
	gpgme_ctx_t gpgme_ctx;
	if(gpgme_new(&gpgme_ctx) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create gpg context.\n");
		exit(-1);
	}

	gpgme_key_t gpgme_signer_key;
	if(gpgme_get_key(gpgme_ctx, OWN_PUBLIC_KEY_FINGERPRINT, &gpgme_signer_key, 0) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not get the signer key from GPGME.\n");
		exit(-1);
	}
	if(gpgme_signers_add(gpgme_ctx, gpgme_signer_key) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not add own key to the signers list.\n");
		exit(-1);
	}

	gpgme_data_t gpgme_plaintext_data;
	if(gpgme_data_new_from_mem(&gpgme_plaintext_data, data, strlen(data), 0) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create GPGME data handle from given plaintext.\n");
		exit(-1);
	}

	gpgme_data_t gpgme_signed_data;
	if(gpgme_data_new(&gpgme_signed_data) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create GPGME data handle for signed data.\n");
		exit(-1);
	}

	int r = gpgme_op_sign(gpgme_ctx, gpgme_plaintext_data, gpgme_signed_data, GPGME_SIG_MODE_NORMAL);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not encrypt and sign plaintext. %s %s\n", gpgme_strsource(r), gpgme_strerror(r));
		exit(-1);
	}
	gpgme_signers_clear(gpgme_ctx);

	//Get encrypted data
	size_t signed_data_size;
	char *signed_data = gpgme_data_release_and_get_mem(gpgme_signed_data, &signed_data_size);

	//Concatenate path
	LOCAL_STR_CAT(path, file_name, path_with_file_name)
	LOCAL_STR_CAT(path_with_file_name, ENCRYPTED_FILE_ENDING, concatenated_path)

	WRITE_BINARY_DATA_TO_FILE(concatenated_path, signed_data, signed_data_size)

	gpgme_free(signed_data);
	gpgme_data_release(gpgme_plaintext_data);
	gpgme_release(gpgme_ctx);
}

//We do not encrypt here, because we do not want to have two decryption operations to decrypt one folder
char *verify_signature_and_path(const char *path, const char *path_to_compare_to, const char *file_name){
	//Concatenate path
	LOCAL_STR_CAT(path, file_name, path_with_file_name)
	LOCAL_STR_CAT(path_with_file_name, ENCRYPTED_FILE_ENDING, concatenated_path)

	gpgme_ctx_t gpgme_ctx;
	if(gpgme_new(&gpgme_ctx) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create gpg context.\n");
		exit(-1);
	}
	gpgme_data_t gpgme_signature;
	if(gpgme_data_new_from_file(&gpgme_signature, concatenated_path, 1) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not read signature from file %s.\n", concatenated_path);
		exit(-1);
	}
	gpgme_data_t gpgme_signed_data;
	if(gpgme_data_new(&gpgme_signed_data) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create GPGME data handle for decrypted data.\n");
		exit(-1);\
	}

	int r = gpgme_op_verify(gpgme_ctx, gpgme_signature, NULL, gpgme_signed_data);

	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not verify signature. %s %s\n", gpgme_strsource(r), gpgme_strerror(r));
		exit(-1);
	}

	size_t signed_data_size;
	char *signed_data_without_zero_at_the_end = gpgme_data_release_and_get_mem(gpgme_signed_data, &signed_data_size);
	char *signed_data = malloc(signed_data_size + 1);
	memcpy(signed_data, signed_data_without_zero_at_the_end, signed_data_size);
	signed_data [signed_data_size] = 0;
	gpgme_free(signed_data_without_zero_at_the_end);
	{
		VERIFY_PATH(signed_data, path_to_compare_to, result_not_needed)
	}

	gpgme_data_release(gpgme_signature);
	gpgme_release(gpgme_ctx);

	return signed_data;
}

//Plain text might contain a hash value which might contain zeros, so plain text length is needed here
void direct_rsa_encrypt_and_save_to_file(const char *plain_text, int plain_text_length, const char *public_key_fingerprint, const char *path, const char *file_name){
	size_t cipher_text_length;
	char *cipher_text = rsa_encrypt(plain_text, plain_text_length, public_key_fingerprint, &cipher_text_length);

	//Concatenate path
	LOCAL_STR_CAT(path, file_name, path_with_file_name)
	LOCAL_STR_CAT(path_with_file_name, public_key_fingerprint, path_with_file_name_and_public_key_fingerprint)
	LOCAL_STR_CAT(path_with_file_name_and_public_key_fingerprint, ENCRYPTED_FILE_ENDING, concatenated_path)

	WRITE_BINARY_DATA_TO_FILE(concatenated_path, cipher_text, cipher_text_length)

	free(cipher_text);
}

//hash value might containt zeros, so hash_value_length is needed.
char *compute_hash_value_from_meta_data(const char *meta_data, int meta_data_length, int *hash_value_length){
	return compute_hash_value_from_meta_data_lib_function(meta_data, meta_data_length, hash_value_length);
}

int get_hash_length(){
	return get_hash_length_lib_function();
}

int directory_contains_authentic_file(char *encrypted_directory, char *file_name){
	LOCAL_STR_CAT(encrypted_directory, file_name, path_to_file_without_file_ending)
	LOCAL_STR_CAT(path_to_file_without_file_ending, ENCRYPTED_FILE_ENDING, path_to_file)
	if(access(path_to_file, F_OK) == 0){
		if(!strcmp(file_name, DECRYPTED_FOLDER_NAME_FILE_NAME)){
			STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_directory, encrypted_directory_name)
			free(verify_signature_and_path(encrypted_directory, encrypted_directory_name, file_name));
		} else {
			free(verify_signature_and_path(encrypted_directory, encrypted_directory, file_name));
		}
		return 1;
	} else {
		return 0;
	}
}
