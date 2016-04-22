#include "gpg_operations.h"
#include <stdlib.h>
#include <stdio.h>

#include "direct_asymmetric_encryption/direct_rsa_encryption.h"

//TODO: Do not do hybrid encryption, only do asymmetric encryption. Else, we only see the data encryption key on the token.
void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name){
	gpgme_ctx_t gpgme_ctx;
	if(gpgme_new(&gpgme_ctx) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create gpg context.\n");
		exit(-1);
	}

	gpgme_key_t gpgme_recipient_key;
	if(gpgme_get_key(gpgme_ctx, public_key_fingerprint, &gpgme_recipient_key, 0) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not get the recipient key from GPGME.\n");
		exit(-1);
	}
	gpgme_key_t gpgme_recipients[] = {gpgme_recipient_key, NULL};
	
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

	gpgme_data_t gpgme_encrypted_data;
	if(gpgme_data_new(&gpgme_encrypted_data) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not create GPGME data handle for encrypted data.\n");
		exit(-1);
	}

	//TODO: Find out, why gpgme gets stuck here. gpg2 works like a charm doing such operations.
	int r = gpgme_op_encrypt_sign(gpgme_ctx, gpgme_recipients, 0, gpgme_plaintext_data, gpgme_encrypted_data);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not encrypt and sign plaintext. %s %s\n", gpgme_strsource(r), gpgme_strerror(r));
		exit(-1);
	}
	gpgme_signers_clear(gpgme_ctx);

	//Get encrypted data
	size_t encrypted_data_size;
	char *encrypted_data = gpgme_data_release_and_get_mem(gpgme_encrypted_data, &encrypted_data_size);
	
	//Concatenate path
	LOCAL_STR_CAT(path, file_name, path_with_file_name)
	LOCAL_STR_CAT(path_with_file_name, public_key_fingerprint, path_with_file_name_and_public_key_fingerprint)
	LOCAL_STR_CAT(path_with_file_name_and_public_key_fingerprint, ENCRYPTED_FILE_ENDING, concatenated_path)
	
	WRITE_BINARY_DATA_TO_FILE(concatenated_path, encrypted_data, encrypted_data_size)
	
	gpgme_free(encrypted_data);
	gpgme_data_release(gpgme_plaintext_data);
	gpgme_release(gpgme_ctx);
}

void direct_rsa_encrypt_and_save_to_file(const char *plain_text, const char *public_key_fingerprint, const char *path, const char *file_name){
	size_t cipher_text_length;
	char *cipher_text = rsa_encrypt(plain_text, public_key_fingerprint, &cipher_text_length);

	//Concatenate path
	LOCAL_STR_CAT(path, file_name, path_with_file_name)
	LOCAL_STR_CAT(path_with_file_name, public_key_fingerprint, path_with_file_name_and_public_key_fingerprint)
	LOCAL_STR_CAT(path_with_file_name_and_public_key_fingerprint, ENCRYPTED_FILE_ENDING, concatenated_path)
	
	WRITE_BINARY_DATA_TO_FILE(concatenated_path, cipher_text, cipher_text_length)

	free(cipher_text);
}

char *compute_hash_value_from_meta_data(const char *meta_data, int meta_data_length){
	return compute_hash_value_from_meta_data_lib_function(meta_data, meta_data_length);
}

int directory_contains_authentic_file(char *encrypted_directory, char *file_name){
	LOCAL_STR_CAT(file_name, OWN_PUBLIC_KEY_FINGERPRINT, file_name_with_fingerprint)
	LOCAL_STR_CAT(encrypted_directory, file_name_with_fingerprint, path_to_file_without_file_ending)
	LOCAL_STR_CAT(path_to_file_without_file_ending, ENCRYPTED_FILE_ENDING, path_to_file)
	if(access(path_to_file, F_OK) == 0){
		if(!strcmp(file_name, DECRYPTED_FOLDER_NAME_FILE_NAME)){
			STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_directory, encrypted_directory_name)
			DECRYPT_DATA_AND_VERIFY_PATH(encrypted_directory, encrypted_directory_name, file_name_with_fingerprint, result)
		} else {
			DECRYPT_DATA_AND_VERIFY_PATH(encrypted_directory, encrypted_directory, file_name_with_fingerprint, result)
		}
		return 1;
	} else {
		return 0;
	}
}
