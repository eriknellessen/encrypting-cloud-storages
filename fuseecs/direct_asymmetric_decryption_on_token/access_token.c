#include <string.h>

#include "util.h"
#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "access_token.h"
#include <assuan.h>

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

u8 *pin;
size_t pin_length;
int pin_set = 0;
static gpg_error_t getpin_cb(void *opaque, const void *buffer, size_t length){
	pin = malloc(length);
	memcpy(pin, buffer, length);
	pin_length = length;
	pin_set = 1;
	//Debug
	printf("PIN in getpin_cb: ");
	int i;
	for(i = 0; i < length; i++){
		printf("%c", pin[i]);
	}
	printf("\n");

	return 0;
}

int get_pin(){
	gpg_error_t err;
	assuan_context_t ctx;
	pin_set = 0;

	err = assuan_new(&ctx);
	if(err){
		fprintf(stderr, "Could not create assuan context.\n");
		return -1;
	}

	//Debug
	assuan_set_log_stream(ctx, stderr);

	const char *argv[1] = {"pinentry"};
	err = assuan_pipe_connect(ctx, "/usr/bin/pinentry", argv, NULL, NULL, NULL, 0);
	if(err){
		fprintf(stderr, "Could not connect to pinentry: %s.\n", gpg_strerror (err));
		return -1;
	}

	err = assuan_transact(ctx, "GETPIN", getpin_cb, NULL, NULL, NULL, NULL, NULL);
	if(err){
		fprintf(stderr, "Could not get PIN (assuan_transact failed).\n");
		return -1;
	}

	while(pin_set == 0);

	assuan_release(ctx);
	return 0;
}

int verify_pin(sc_card_t *card){
	int tries_left, r;
	r = get_pin();
	if(r){
		fprintf(stderr, "Could not get PIN from user.\n");
		return -1;
	}

	r = sc_verify(card, SC_AC_CHV, 2, pin, pin_length, &tries_left);
	if(r){
		fprintf(stderr, "Could not verify PIN: %s\n", sc_strerror(r));
		return -1;
	}

	free(pin);

	return 0;
}

int decipher(const u8 *cipher_text, int cipher_text_length, u8 **plain_text, sc_card_t *card){
	int r;
	int plain_text_length = cipher_text_length;

	/* Debug */
	{
	int i;
		printf("Cipher text before decryption on token: ");
		for(i = 0; i < cipher_text_length; i++){
			printf("%02X ", cipher_text[i]);
		}
		printf("\n");
	}

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
	sc_context_t *ctx = card->ctx;
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

	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	return 0;
}

int send_meta_data_to_token(const char *meta_data, int meta_data_length){
	sc_card_t *card;

	printf("File: %s Line: %i\n", __FILE__, __LINE__);
	//Connect to the card
	if(connect_to_card(&card) != 0){
		return -1;
	}
	sc_context_t *ctx = card->ctx;
	printf("File: %s Line: %i\n", __FILE__, __LINE__);

	sc_apdu_t apdu;
	u8 apdu_case = SC_APDU_CASE_3;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	//As stated in ISO7816-4, 0x23 is not taken
	sc_format_apdu(card, &apdu, apdu_case, 0x23, 0x00, 0x00);
	//We do not expect the smartphone to support extended APDUs, so we use APDU chaining
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	//Only status word is expected
	apdu.lc = meta_data_length;
	apdu.data = (u8 *) meta_data;
	apdu.datalen = meta_data_length;
	apdu.le = 0;
	apdu.resp = NULL;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	LOG_FUNC_RETURN(card->ctx, 0);
}
