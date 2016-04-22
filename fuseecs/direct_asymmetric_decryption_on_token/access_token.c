#include <string.h>

#include "util.h"
#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "access_token.h"

int connect_to_card(sc_card_t **card){
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	int r;
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 0;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "failed to establish context: %s\n", sc_strerror(r));
		return -1;
	}

	//This would fail, because the OpenPGP card driver in OpenSC expects more output than 0x9000 when
	//sending select application. So we changed the driver.
	printf("Card: %p\n", card);
	r = util_connect_card(ctx, card, NULL, 0, 0);
	if(r){
		fprintf(stderr, "failed to connect to card: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Card: %p\n", card);
	/* check card type */
	sc_card_t *card_pointer = *card;
	if((card_pointer->type != SC_CARD_TYPE_OPENPGP_V1) &&
	   (card_pointer->type != SC_CARD_TYPE_OPENPGP_V2)){
		util_error("not an OpenPGP card");
		return -1;
	}

	return 0;
}

int set_rsa_decryption_security_environment(sc_card_t *card){
	int r;
	sc_security_env_t security_env = {
		.flags = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT,
		.operation = SC_SEC_OPERATION_DECIPHER,
		.algorithm = SC_ALGORITHM_RSA,
		.key_ref = {0x02},
		.key_ref_len = 1,
	};
	r = sc_set_security_env(card, &security_env, 0);
	if(r){
		fprintf(stderr, "Could not set security environment: %s\n", sc_strerror(r));
		return -1;
	}

	return 0;
}

int verify_pin(sc_card_t *card){
	int tries_left, r;
	//TODO: Get PIN from user/card reader
	const u8 pin_value [] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
	r = sc_verify(card, SC_AC_CHV, 2, pin_value, sizeof pin_value, &tries_left);
	if(r){
		fprintf(stderr, "Could not verify PIN: %s\n", sc_strerror(r));
		return -1;
	}

	return 0;
}

int decipher(const u8 *cipher_text, int cipher_text_length, u8 **plain_text, sc_card_t *card){
	int r;
	int plain_text_length = cipher_text_length;
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	printf("plain_text_length: %i\n", plain_text_length);
	*plain_text = malloc(plain_text_length + 1);
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	r = sc_decipher(card, cipher_text, cipher_text_length, *plain_text, plain_text_length);
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	if(r < 0 || r > plain_text_length){
		fprintf(stderr, "Could not decipher: %s\n", sc_strerror(r));
		return -1;
	}

	(*plain_text)[r] = 0;
	//Debug
	printf("plain_text: %s\n", *plain_text);

	return 0;
}

//plain_text will most likely not contain zeros, so we do not need to return the length
int rsa_decrypt_on_token(const char *cipher_text, int cipher_text_length, char **plain_text){
	sc_card_t *card;

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	//Connect to the card
	if(connect_to_card(&card) != 0){
		return -1;
	}
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	//Set security environment
	if(set_rsa_decryption_security_environment(card) != 0){
		return -1;
	}
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	//Verify PIN
	if(verify_pin(card) != 0){
		return -1;
	}
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	//Do the actual deciphering
	if(decipher((u8 *) cipher_text, cipher_text_length, (u8 **) plain_text, card) != 0){
		return -1;
	}
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	return 0;
}

// int main(int argc, char *argv []){
// 	u8 cipher_text [] = {0x64, 0x9d, 0xea, 0x56, 0x34, 0x06, 0x63, 0x2d, 0x11, 0xc4, 0x9e, 0xab, 0x87, 0x5a, 0xc4, 0x67, 0x4a, 0x19, 0x82, 0x83, 0x62, 0x4c, 0xb8, 0x62, 0x71, 0xa5, 0xc2, 0x91, 0xb2, 0x57, 0x3b, 0xf5, 0xdc, 0xd8, 0xc2, 0xa9, 0xf5, 0x3e, 0xee, 0xae, 0x8b, 0xef, 0x4c, 0x3c, 0xcd, 0xb3, 0x3b, 0x61, 0xc0, 0x9a, 
// 0x33, 0x23, 0xeb, 0xa4, 0xef, 0xb1, 0xcf, 0xaa, 0x2f, 0x9f, 0x92, 0x02, 0x9b, 0xa5, 0x2f, 0x7c, 0xbf, 0xf3, 0x70, 0xf1, 0xa4, 0xa3, 0xc3, 0xf8, 0xdd, 0xc5, 0x8f, 0x99, 0x07, 0xd1, 0x57, 0x2d, 0xfe, 0x61, 0x74, 0xa6, 0xb6, 0x08, 0xaf, 0xf5, 0x2b, 0x74, 0x2b, 0xab, 0x20, 0x7d, 0xec, 0xbc, 0x62, 0xa0, 
// 0x7a, 0x34, 0x67, 0x89, 0x07, 0x84, 0x2e, 0x4b, 0x0b, 0x0e, 0xbe, 0x76, 0xb0, 0x25, 0x3a, 0x18, 0xe9, 0x07, 0xce, 0x30, 0x3a, 0x31, 0x22, 0x08, 0x37, 0x69, 0x29, 0xcd, 0xa8, 0x68, 0xf9, 0x00, 0xe0, 0x0b, 0x05, 0x83, 0xb7, 0xcd, 0x85, 0xae, 0x6d, 0xd2, 0x0a, 0x2d, 0xad, 0xdd, 0x66, 0x8a, 0x4b, 0x36, 
// 0xe3, 0x92, 0xfc, 0x20, 0x2e, 0x09, 0xa3, 0x7c, 0x6e, 0xf3, 0x6a, 0xb0, 0x46, 0x96, 0xe8, 0x8c, 0x8d, 0xc9, 0x60, 0x8a, 0x3c, 0xa7, 0xde, 0xc7, 0x2a, 0x80, 0xea, 0xed, 0x0e, 0x5a, 0x81, 0x5c, 0xed, 0x62, 0xe8, 0x1e, 0xd6, 0xdd, 0x11, 0x7f, 0x77, 0xd3, 0x22, 0xc9, 0x83, 0x5e, 0x90, 0xba, 0x82, 0x84, 
// 0xc9, 0x80, 0x9a, 0x81, 0x83, 0x56, 0x76, 0xab, 0x17, 0xc7, 0x90, 0x4f, 0x61, 0x52, 0x99, 0x77, 0xde, 0xb7, 0x6e, 0xf0, 0x51, 0xd7, 0x23, 0x0d, 0x67, 0xd4, 0x3c, 0x1d, 0x44, 0x82, 0x6a, 0x58, 0xcb, 0x1d, 0x30, 0xa3, 0x55, 0x8e, 0x30, 0x95, 0x15, 0x64, 0xe8, 0x42, 0x5f, 0xbd, 0xa9, 0x47, 0x13, 0x62, 
// 0xb5, 0x16, 0x4a, 0xe7, 0xf5, 0xa2};
// 	unsigned char *plain_text = NULL;
// 	int r = rsa_decrypt_on_token(cipher_text, sizeof cipher_text, &plain_text);
// 	if(r != 0){
// 		printf("rsa_decrypt_on_token failed.\n");
// 		return -1;
// 	}
// 	printf("plain_text: %s\n", plain_text);
// 	free(plain_text);
// 
// 	return 0;
// }
