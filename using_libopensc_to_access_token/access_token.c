#include <string.h>

#include "util.h"
#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"

int main(int argc, char *argv []){
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int r;

	/* connect to the card */
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 0;
	//ctx_param.app_name = app_name;
	
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	r = sc_context_create(&ctx, &ctx_param);
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	if (r) {
		util_fatal("failed to establish context: %s\n",
			sc_strerror(r));
		return -1;
	}

	/*
	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}
	*/

	//This would fail, because the OpenPGP card driver in OpenSC expects more output than 0x9000 when
	//sending select application. So we changed the driver.
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	r = util_connect_card(ctx, &card, /*opt_reader*/NULL, /*opt_wait*/0, /*verbose*/0);
	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	if(r){
		util_fatal("failed to connect to card: %s\n",
			sc_strerror(r));
		printf("File: %s Line: %i\n", __FILE__, __LINE__);
		return -1;
	}

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	/* check card type */
	if((card->type != SC_CARD_TYPE_OPENPGP_V1) &&
	   (card->type != SC_CARD_TYPE_OPENPGP_V2)){
		util_error("not an OpenPGP card");
		printf("File: %s Line: %i\n", __FILE__, __LINE__);
		return -1;
	}
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	//Set security environment
	sc_security_env_t security_env = {
		.flags = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT,
		.operation = SC_SEC_OPERATION_DECIPHER,
		.algorithm = SC_ALGORITHM_RSA,
		.key_ref = {0x02},
		.key_ref_len = 1,
	};
	r = sc_set_security_env(card, &security_env, 0);
	if(r){
		util_fatal("Could not set security environment: %s\n", sc_strerror(r));
		printf("File: %s Line: %i\n", __FILE__, __LINE__);
		return -1;
	}

	//Verify PIN
	int tries_left;
	const u8 pin_value [] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
	r = sc_verify(card, SC_AC_CHV, 2, pin_value, sizeof pin_value, &tries_left);
	if(r){
		util_fatal("Could not verify PIN: %s\n", sc_strerror(r));
		printf("File: %s Line: %i\n", __FILE__, __LINE__);
		return -1;
	}

	//Decipher
	/*u8 cipher_text [] = {0x00, 0xB1, 0xF1, 0xD6, 0x5D, 0xB0, 0xCB, 0xC7, 0xDF, 0xC0, 0x18, 0x1A, 0xE6, 0x50, 0x5B, 0xD0, 0x40, 0x95, 0x8C, 0xC0, 0x3E, 0x37, 0x7E, 0xFB, 0x47, 0x43, 0x3E, 0x73, 0xD4, 0x65, 0x3C, 0xA1, 0x3D, 0xDF, 0x24, 0x9C, 0x1C, 0x49, 0x6C, 0x33, 0x83, 0xD1, 0x86, 0x01, 0x13, 0xD7, 0xA5, 0x76, 0x35, 0xC9, 
0xC5, 0x17, 0x26, 0x9D, 0xEB, 0x4B, 0x9C, 0x08, 0x53, 0xC2, 0x5F, 0x3B, 0x61, 0xC8, 0x31, 0x9C, 0x42, 0xEB, 0xD4, 0xEE, 0x5A, 0xD8, 0x2F, 0x99, 0x35, 0x6D, 0xA1, 0xF6, 0x95, 0x01, 0x9B, 0xB3, 0xCB, 0xAA, 0x9D, 0x0D, 0x29, 0xC9, 0x85, 0x6D, 0xAF, 0x43, 0x61, 0x6D, 0xDE, 0x43, 0x2D, 0x38, 0x66, 0xB7, 
0x5B, 0x1B, 0x82, 0x66, 0x1C, 0xB0, 0x01, 0x1A, 0xD9, 0xAC, 0x1E, 0xC0, 0xBB, 0x02, 0x7A, 0x81, 0xE3, 0x77, 0x47, 0xA2, 0x38, 0x87, 0xDE, 0x91, 0xFC, 0x98, 0x2E, 0xFA, 0x0F, 0x92, 0x2E, 0x64, 0x74, 0xC4, 0xA3, 0xE4, 0x8E, 0xDE, 0x81, 0xDE, 0xC8, 0x61, 0x1C, 0xF4, 0x08, 0x4B, 0xB4, 0xCF, 0x57, 0x3F, 
0x25, 0x7D, 0xBC, 0x35, 0xDA, 0x96, 0x47, 0x59, 0x75, 0xC0, 0x85, 0x2E, 0x1A, 0x89, 0x86, 0xFB, 0xA5, 0x9A, 0xFD, 0xF0, 0x99, 0x0F, 0x4F, 0x33, 0xD3, 0x6D, 0x70, 0xDD, 0x28, 0xB8, 0xED, 0xA1, 0x67, 0x08, 0x18, 0x13, 0x16, 0x41, 0x44, 0x3A, 0x81, 0xA9, 0x1C, 0xF0, 0x18, 0x7E, 0x44, 0x4E, 0x0A, 0x1C, 
0x0D, 0xD7, 0xBA, 0x1B, 0x68, 0x88, 0x88, 0x09, 0x98, 0x08, 0x2D, 0x56, 0xA0, 0xA5, 0x8E, 0xF4, 0xC8, 0x22, 0x65, 0xE6, 0x5E, 0x1D, 0x0C, 0x77, 0xFD, 0x0F, 0x05, 0x02, 0x40, 0xA4, 0xB1, 0x7E, 0x80, 0x81, 0xA1, 0xDB, 0xE8, 0x0F, 0x17, 0x3F, 0xD7, 0xF7, 0x8A, 0x79, 0xF7, 0x3D, 0xE2, 0x66, 0x40, 0xB4, 
0x1D, 0xBC, 0xAE, 0x4E};*/
	u8 cipher_text [] = {0x64, 0x9d, 0xea, 0x56, 0x34, 0x06, 0x63, 0x2d, 0x11, 0xc4, 0x9e, 0xab, 0x87, 0x5a, 0xc4, 0x67, 0x4a, 0x19, 0x82, 0x83, 0x62, 0x4c, 0xb8, 0x62, 0x71, 0xa5, 0xc2, 0x91, 0xb2, 0x57, 0x3b, 0xf5, 0xdc, 0xd8, 0xc2, 0xa9, 0xf5, 0x3e, 0xee, 0xae, 0x8b, 0xef, 0x4c, 0x3c, 0xcd, 0xb3, 0x3b, 0x61, 0xc0, 0x9a, 
0x33, 0x23, 0xeb, 0xa4, 0xef, 0xb1, 0xcf, 0xaa, 0x2f, 0x9f, 0x92, 0x02, 0x9b, 0xa5, 0x2f, 0x7c, 0xbf, 0xf3, 0x70, 0xf1, 0xa4, 0xa3, 0xc3, 0xf8, 0xdd, 0xc5, 0x8f, 0x99, 0x07, 0xd1, 0x57, 0x2d, 0xfe, 0x61, 0x74, 0xa6, 0xb6, 0x08, 0xaf, 0xf5, 0x2b, 0x74, 0x2b, 0xab, 0x20, 0x7d, 0xec, 0xbc, 0x62, 0xa0, 
0x7a, 0x34, 0x67, 0x89, 0x07, 0x84, 0x2e, 0x4b, 0x0b, 0x0e, 0xbe, 0x76, 0xb0, 0x25, 0x3a, 0x18, 0xe9, 0x07, 0xce, 0x30, 0x3a, 0x31, 0x22, 0x08, 0x37, 0x69, 0x29, 0xcd, 0xa8, 0x68, 0xf9, 0x00, 0xe0, 0x0b, 0x05, 0x83, 0xb7, 0xcd, 0x85, 0xae, 0x6d, 0xd2, 0x0a, 0x2d, 0xad, 0xdd, 0x66, 0x8a, 0x4b, 0x36, 
0xe3, 0x92, 0xfc, 0x20, 0x2e, 0x09, 0xa3, 0x7c, 0x6e, 0xf3, 0x6a, 0xb0, 0x46, 0x96, 0xe8, 0x8c, 0x8d, 0xc9, 0x60, 0x8a, 0x3c, 0xa7, 0xde, 0xc7, 0x2a, 0x80, 0xea, 0xed, 0x0e, 0x5a, 0x81, 0x5c, 0xed, 0x62, 0xe8, 0x1e, 0xd6, 0xdd, 0x11, 0x7f, 0x77, 0xd3, 0x22, 0xc9, 0x83, 0x5e, 0x90, 0xba, 0x82, 0x84, 
0xc9, 0x80, 0x9a, 0x81, 0x83, 0x56, 0x76, 0xab, 0x17, 0xc7, 0x90, 0x4f, 0x61, 0x52, 0x99, 0x77, 0xde, 0xb7, 0x6e, 0xf0, 0x51, 0xd7, 0x23, 0x0d, 0x67, 0xd4, 0x3c, 0x1d, 0x44, 0x82, 0x6a, 0x58, 0xcb, 0x1d, 0x30, 0xa3, 0x55, 0x8e, 0x30, 0x95, 0x15, 0x64, 0xe8, 0x42, 0x5f, 0xbd, 0xa9, 0x47, 0x13, 0x62, 
0xb5, 0x16, 0x4a, 0xe7, 0xf5, 0xa2};
	size_t plain_text_length = sizeof cipher_text;
	u8 *plain_text = malloc(plain_text_length);
	r = sc_decipher(card, cipher_text, sizeof cipher_text, plain_text, plain_text_length);
	printf("r: %i\n", r);
	LOG_TEST_RET(card->ctx, r, "Card returned error");
	/*
	if(r){
		util_fatal("Could not decipher: %s\n",
			sc_strerror(r));
		printf("File: %s Line: %i\n", __FILE__, __LINE__);
	}
	*/
	plain_text[r] = 0;
	printf("plain_text: %s\n", plain_text);

	return 0;
}
