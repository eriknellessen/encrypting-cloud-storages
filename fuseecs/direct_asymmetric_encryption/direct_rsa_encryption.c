#include <gcrypt.h>
#include <gpgme.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "configuration.h"

#define BEGIN_OF_PGP_DUMP_COMMAND "echo \""
#define ESCAPED_QUOTA "\""
#define END_OF_PGPDUMP_COMMAND " | python "CMAKE_INSTALL_FULL_BINDIR"/parse_public_key.py"
#define BUFFER_SIZE 1024

gcry_mpi_t get_mpi_from_sexp (gcry_sexp_t sexp, const char *item, int mpifmt){
	gcry_sexp_t list;
	gcry_mpi_t data;

	list = gcry_sexp_find_token (sexp, item, 0);
	assert (list);
	data = gcry_sexp_nth_mpi (list, 1, mpifmt);
	assert (data);
	gcry_sexp_release (list);
	return data;
}

char *get_public_key_from_gpg(const char *public_key_fingerprint){
	gpgme_error_t r;
	gpgme_ctx_t ctx;
	gpgme_data_t public_key_data;
	size_t length;
	//TODO: Not needed, when called from fuseecs
	gpgme_check_version(NULL);

	r = gpgme_new(&ctx);
	gpgme_set_armor(ctx, 1);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	r = gpgme_data_new(&public_key_data);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	r = gpgme_op_export(ctx, public_key_fingerprint, GPGME_EXPORT_MODE_MINIMAL, public_key_data);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}

	char *result_without_ending_zero = gpgme_data_release_and_get_mem(public_key_data, &length);
	char *result = malloc(sizeof(char) * (length + 1));
	memcpy(result, result_without_ending_zero, length);
	gpgme_free(result_without_ending_zero);
	result[length] = 0;
	return result;
}

char *get_modulus_and_exponent_from_pgpdump(const char *public_key_string){
	int pgpdump_command_length = strlen(BEGIN_OF_PGP_DUMP_COMMAND) + strlen(public_key_string) + 1 + strlen(END_OF_PGPDUMP_COMMAND) + 1;
	char pgpdump_command [pgpdump_command_length];
	memcpy(pgpdump_command, BEGIN_OF_PGP_DUMP_COMMAND, strlen(BEGIN_OF_PGP_DUMP_COMMAND));
	memcpy(pgpdump_command + strlen(BEGIN_OF_PGP_DUMP_COMMAND), public_key_string, strlen(public_key_string));
	memcpy(pgpdump_command + strlen(BEGIN_OF_PGP_DUMP_COMMAND) + strlen(public_key_string), ESCAPED_QUOTA, strlen(ESCAPED_QUOTA));
	memcpy(pgpdump_command + + strlen(BEGIN_OF_PGP_DUMP_COMMAND) + strlen(public_key_string) + 1, END_OF_PGPDUMP_COMMAND, strlen(END_OF_PGPDUMP_COMMAND));
	pgpdump_command [pgpdump_command_length - 1] = 0;

	printf("pgpdump_command %s\n", pgpdump_command);

	char buffer[BUFFER_SIZE];
	char *data = NULL;
	int size;
	int pos = 0;

	FILE *pipe = popen(pgpdump_command, "r");

	if(pipe){
		while(fgets(buffer, BUFFER_SIZE, pipe) != NULL) {
			size = strlen(buffer);
			data = realloc(data, pos + size);
			memcpy(&data[pos], buffer, size);
			pos += size;
		}
		data = realloc(data, pos + 1);
		data[pos] = 0;
	}

	int returnValue = pclose(pipe);
	//Get the data
	if(!(data && returnValue == 0)){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}

	return data;
}

char *copy_until_newline(const char *data){
	int length;
	char *end = strchr(data, '\n');
	length = end - data;
	char *returnValue = malloc(sizeof(char) * (length + 1));
	memcpy(returnValue, data, length);
	returnValue[length] = 0;
	return returnValue;
}

/*-- Macros to replace ctype ones to avoid locale problems. --*/
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
/* The atoi macros assume that the buffer has only valid digits. */
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

/* Convert STRING consisting of hex characters into its binary
   representation and store that at BUFFER.  BUFFER needs to be of
   LENGTH bytes.  The function checks that the STRING will convert
   exactly to LENGTH bytes. The string is delimited by either end of
   string or a white space character.  The function returns -1 on
   error or the length of the parsed string.  */
int hex2bin(const char *string, void *buffer, size_t length){
	int i;
	const char *s = string;

	for (i=0; i < length; ){
		if (!hexdigitp (s) || !hexdigitp (s+1))
			return -1;           /* Invalid hex digits. */
		((unsigned char*)buffer)[i++] = xtoi_2 (s);
		s += 2;
	}
	if (*s && (!isascii (*s) || !isspace (*s)) )
		return -1;             /* Not followed by Nul or white space.  */
	if (i != length)
		return -1;             /* Not of expected length.  */
	if (*s)
		s++; /* Skip the delimiter. */
	return s - string;
}

char *create_binary_string_from_hex_string(const char *hex_string, int *binary_string_length){
	*binary_string_length = strlen(hex_string) / 2;
	char *binary_string = malloc(sizeof(char) * (*binary_string_length + 1));
	if(hex2bin(hex_string, binary_string, *binary_string_length) == -1){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	binary_string[*binary_string_length] = 0;
	return binary_string;
}

gcry_mpi_t get_gcry_mpi_t_from_binary_string(const char *binary_string, int binary_string_length){
	gcry_error_t rc;
	gcry_mpi_t mpi = gcry_mpi_new(0);
	size_t scanned_length;
	rc = gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, binary_string, binary_string_length, &scanned_length);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}

	return mpi;
}

//Cipher text might contain zeros, so result_length is necessary
char *rsa_encrypt(const char *plain_text, const char *public_key_fingerprint, size_t *result_length){
	//Get public key from gpg
	char *public_key_string = get_public_key_from_gpg(public_key_fingerprint);
	//Debug
	printf("public_key_string: %s\n", public_key_string);

	//Get modulus and exponent from pgpdump
	char *modulus_and_exponent = get_modulus_and_exponent_from_pgpdump(public_key_string);
	free(public_key_string);
	printf("Modulus and exponent received from pgpdump: %s\n", modulus_and_exponent);

	//Get modulus and exponent as separate strings
	char *modulus_as_hex_string = copy_until_newline(modulus_and_exponent);
	char *exponent_as_hex_string = copy_until_newline(modulus_and_exponent + strlen(modulus_as_hex_string) + 1);
	free(modulus_and_exponent);
	//Debug
	printf("modulus_as_hex_string: %s\n", modulus_as_hex_string);
	printf("exponent_as_hex_string: %s\n", exponent_as_hex_string);

	//Convert to binary strings, as needed by libgcrypt
	//From here on, strings might contain zeros. So we always have to remember the length
	int modulus_as_binary_string_length;
	char *modulus_as_binary_string = create_binary_string_from_hex_string(modulus_as_hex_string, &modulus_as_binary_string_length);
	free(modulus_as_hex_string);
	int exponent_as_binary_string_length;
	char *exponent_as_binary_string = create_binary_string_from_hex_string(exponent_as_hex_string, &exponent_as_binary_string_length);
	free(exponent_as_hex_string);

	//Create mpis from modulus, exponent and plain_text
	gcry_mpi_t modulus = get_gcry_mpi_t_from_binary_string(modulus_as_binary_string, modulus_as_binary_string_length);
	gcry_mpi_t exponent = get_gcry_mpi_t_from_binary_string(exponent_as_binary_string, exponent_as_binary_string_length);
	//Debug
	gcry_log_debugmpi("modulus", modulus);
	gcry_log_debugmpi("exponent", exponent);
	free(modulus_as_binary_string);
	free(exponent_as_binary_string);

	//Create the expected sexps
	gcry_sexp_t s_pkey = NULL;
	gcry_sexp_t s_data = NULL;
	gcry_sexp_t s_ciph = NULL;
	//Building s-expression for key and data
	gcry_error_t rc;
	rc = gcry_sexp_build(&s_pkey, NULL, "(public-key(rsa(n%M)(e%M)))", modulus, exponent);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_mpi_release(modulus);
	gcry_mpi_release(exponent);
	//Debug
	gcry_log_debugsxp ("s_pkey", s_pkey);
	rc = gcry_sexp_build(&s_data, NULL, "(data(flags pkcs1)(value %s))", plain_text);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	//Debug
	gcry_log_debugsxp ("s_data", s_data);

	//Do the actual encryption
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	//Get the result
	//Debug
	gcry_log_debugsxp("s_ciph", s_ciph);
	gcry_mpi_t result_as_mpi = get_mpi_from_sexp(s_ciph, "a", GCRYMPI_FMT_USG);
	gcry_sexp_release(s_ciph);
	//Debug
	gcry_log_debugmpi("result_as_mpi", result_as_mpi);
	unsigned char *result;
	rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &result, result_length, result_as_mpi);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_mpi_release(result_as_mpi);

	return (char *) result;
}

char *compute_hash_value_from_meta_data_lib_function(const char *meta_data, int meta_data_length){
	int hash_value_length = gcry_md_get_algo_dlen(HASH_ALGORITHM) + 1;
	char *hash_value = malloc(hash_value_length);
	gcry_md_hash_buffer(HASH_ALGORITHM, hash_value, meta_data, meta_data_length);
	hash_value[hash_value_length - 1] = 0;
	return hash_value;
}

// int main(int argc, char *argv []){
// 	size_t cipher_text_length;
// 	unsigned char *cipher_text = rsa_encrypt("00010203040506070809101112131415", "FD654C6F", &cipher_text_length);
// 	printf("cipher_text (%i bytes): ", cipher_text_length);
// 	int i;
// 	for(i = 0; i < cipher_text_length; i++){
// 		printf("%c", cipher_text[i]);
// 	}
// 	printf("\n");
// 	free(cipher_text);
// 
// 	return 0;
// }
