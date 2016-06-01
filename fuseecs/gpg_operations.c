#include "gpg_operations.h"
#include <stdlib.h>
#include <stdio.h>

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

	if(gpgme_op_encrypt_sign(gpgme_ctx, gpgme_recipients, 0, gpgme_plaintext_data, gpgme_encrypted_data) != GPG_ERR_NO_ERROR){
		fprintf(stderr, "Could not encrypt and sign plaintext.\n");
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

//TODO: Implement this
int signer_verification_needed(const char *path){
	//Not needed, if signature with our own private key or we already placed a signed file in the directory, which says, that we already checked the signature (containing the verified signer, we need to check if the current signer is the same)
	return 1;
}