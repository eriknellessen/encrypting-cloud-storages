#include "data_operations.h"
#include <stdlib.h>
#include <stdio.h>

//gpg2 --sign --local-user A6506F46 --encrypt -r A6506F46 --output xxx.txt.gpg xxx.txt
//TODO: By piping the data into gpg, the password is visible for other processes. Would be better to use GPGME here.
void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name){
	LOCAL_STR_CAT("echo \'", data, cmd0)
	LOCAL_STR_CAT(cmd0, "\'", cmd1)
	LOCAL_STR_CAT(cmd1, " | ", cmd2)
	LOCAL_STR_CAT(cmd2, GPG_SIGN_COMMAND, cmd3)
	LOCAL_STR_CAT(cmd3, OWN_PUBLIC_KEY_FINGERPRINT, cmd4)
	LOCAL_STR_CAT(cmd4, GPG_ENCRYPTION_OPTION, cmd5)
	LOCAL_STR_CAT(cmd5, public_key_fingerprint, cmd6)
	LOCAL_STR_CAT(cmd6, GPG_OUTPUT_OPTION, cmd7)
	LOCAL_STR_CAT(cmd7, path, cmd8)
	LOCAL_STR_CAT(cmd8, file_name, cmd9)
	LOCAL_STR_CAT(cmd9, public_key_fingerprint, cmd10)
	LOCAL_STR_CAT(cmd10, ENCRYPTED_FILE_ENDING, concatenated_cmd)
	
	//Debug
	printf("concatenated_cmd: %s\n", concatenated_cmd);
	
	if(system(concatenated_cmd)){
		fprintf(stderr, "Could not sign and encrypt data.\n");
		exit(-1);
	}
} 
