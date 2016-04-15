#include <gcrypt.h>
#include <gpgme.h>
#include <string.h>
#include <assert.h>

#define OWN_PUBLIC_KEY_FINGERPRINT "267FB332"
#define BEGIN_OF_PGP_DUMP_COMMAND "echo \""
#define ESCAPED_QUOTA "\""
#define END_OF_PGPDUMP_COMMAND " | python parse_public_key.py"
#define BUFFER_SIZE 1024

gcry_mpi_t
get_mpi_from_sexp (gcry_sexp_t sexp, const char *item, int mpifmt)
{
  gcry_sexp_t list;
  gcry_mpi_t data;

  list = gcry_sexp_find_token (sexp, item, 0);
  assert (list);
  data = gcry_sexp_nth_mpi (list, 1, mpifmt);
  assert (data);
  gcry_sexp_release (list);
  return data;
}

char *get_public_key_from_gpg(int *length){
	gpgme_error_t r;
	gpgme_ctx_t ctx;
	gpgme_data_t public_key_data;
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
	r = gpgme_op_export(ctx, OWN_PUBLIC_KEY_FINGERPRINT, GPGME_EXPORT_MODE_MINIMAL, public_key_data);
	if(r != GPG_ERR_NO_ERROR){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}

	return gpgme_data_release_and_get_mem(public_key_data, length);
}

char *get_data_from_pgpdump(char *public_key_string, int public_key_string_length){
	int pgpdump_command_length = strlen(BEGIN_OF_PGP_DUMP_COMMAND) + public_key_string_length + 1 + strlen(END_OF_PGPDUMP_COMMAND) + 1;
	char pgpdump_command [pgpdump_command_length];
	memcpy(pgpdump_command, BEGIN_OF_PGP_DUMP_COMMAND, strlen(BEGIN_OF_PGP_DUMP_COMMAND));
	memcpy(pgpdump_command + strlen(BEGIN_OF_PGP_DUMP_COMMAND), public_key_string, public_key_string_length);
	memcpy(pgpdump_command + strlen(BEGIN_OF_PGP_DUMP_COMMAND) + public_key_string_length, ESCAPED_QUOTA, strlen(ESCAPED_QUOTA));
	memcpy(pgpdump_command + + strlen(BEGIN_OF_PGP_DUMP_COMMAND) + public_key_string_length + 1, END_OF_PGPDUMP_COMMAND, strlen(END_OF_PGPDUMP_COMMAND));
	pgpdump_command [pgpdump_command_length - 1] = 0;
	gpgme_free(public_key_string);
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
	}

	int returnValue = pclose(pipe);
	//Get the data
	if(!(data && returnValue == 0)){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}

	return data;
}

char *copy_until_newline(char *data, int *length){
	char *end = strchr(data, '\n');
	*length = end - data;
	char *returnValue = malloc(sizeof(char) * (*length + 1));
	memcpy(returnValue, data, *length);
	returnValue[*length] = 0;
	return returnValue;
}

/*-- Macros to replace ctype ones to avoid locale problems. --*/
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
  /* Note this isn't identical to a C locale isspace() without \f and
     \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define xtoi_4(p)   ((xtoi_2(p) * 256) + xtoi_2((p)+2))

/* Convert STRING consisting of hex characters into its binary
   representation and store that at BUFFER.  BUFFER needs to be of
   LENGTH bytes.  The function checks that the STRING will convert
   exactly to LENGTH bytes. The string is delimited by either end of
   string or a white space character.  The function returns -1 on
   error or the length of the parsed string.  */
int
hex2bin (const char *string, void *buffer, size_t length)
{
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

int main(int argc, char *argv []){
	//Get public key from gpg
	int public_key_string_length;
	char *public_key_string = get_public_key_from_gpg(&public_key_string_length);
	printf("public_key_string: ");
	int i;
	for(i = 0; i < public_key_string_length; i++){
		printf("%c", public_key_string[i]);
	}
	printf("\n");

	//Get modulus and exponent from pgpdump
	char *data = get_data_from_pgpdump(public_key_string, public_key_string_length);

	printf("Data received from command: %s\n", data);

	//Search for the end of the modulus
	int length_of_modulus;
	char *modulus_as_string = copy_until_newline(data, &length_of_modulus);

	int length_of_exponent;
	char *exponent_as_string = copy_until_newline(data + length_of_modulus + 1, &length_of_exponent);

	free(data);

	//Convert to binary strings, as needed by libgcrypt
	int modulus_binary_length = length_of_modulus / 2;
	char modulus_binary [modulus_binary_length];
	if(hex2bin(modulus_as_string, modulus_binary, modulus_binary_length) == -1){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	free(modulus_as_string);
	
	int exponent_binary_length = length_of_exponent / 2;
	char exponent_binary [exponent_binary_length];
	if(hex2bin(exponent_as_string, exponent_binary, exponent_binary_length) == -1){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	free(exponent_as_string);
	
	/*
	unsigned char modulus_as_string [] = "28345400211331885399197755179428998581157917022961706265150737856573795851095984596035535241477875072408753439468538491300205388558241231579899845178594445819325759330491785016675249726423467864494805355793810604782024727310461037827871568040670636392677521102404559007358527571034535584493231394849789121288531773271661187795373653926443895708120690428975301713604714444458045981497449446210432923821860064633346179860898080214464767252691431467948211784151336681312221975826890857525122324248088442898798970838498767158333729482958927106672362769723224488136278573161735072080846747915524471921218097584994694609077";
	int length_of_modulus = strlen(modulus_as_string);
	unsigned char exponent_as_string [] = "65537";
	int length_of_exponent = strlen(exponent_as_string);
	*/

	//TODO: Convert the decimal string to the format needed for pkey[0] and pkey[1]. What format is this?

	gcry_error_t rc;
	gcry_mpi_t modulus = gcry_mpi_new(0);
	size_t modulus_scanned_length;
	gcry_mpi_t exponent = gcry_mpi_new(0);
	size_t exponent_scanned_length;
	rc = gcry_mpi_scan(&modulus, GCRYMPI_FMT_USG, modulus_binary, modulus_binary_length, &modulus_scanned_length);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	printf("modulus_scanned_length: %i\n", modulus_scanned_length);
	rc = gcry_mpi_scan(&exponent, GCRYMPI_FMT_USG, exponent_binary, exponent_binary_length, &exponent_scanned_length);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	printf("exponent_scanned_length: %i\n", exponent_scanned_length);

	gcry_log_debugmpi ("modulus", modulus);
	gcry_log_debugmpi ("exponent", exponent);
	/*
	print_mpi(modulus);
	print_mpi(exponent);
	*/

// 	gcry_mpi_t data = NULL;
// 	PKT_public_key *pk = NULL;
//
	//Taken from libgcrypt/g10/pkglue.c, function int pk_encrypt (pubkey_algo_t algo, gcry_mpi_t *resarr, gcry_mpi_t data, PKT_public_key *pk, gcry_mpi_t *pkey)
	gcry_sexp_t s_ciph = NULL;
	gcry_sexp_t s_data = NULL;
	gcry_sexp_t s_pkey = NULL;

	//Building s-expression for key and data
	rc = gcry_sexp_build(&s_pkey, NULL, "(public-key(rsa(n%M)(e%M)))", modulus, exponent);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_mpi_release(modulus);
	gcry_mpi_release(exponent);
	gcry_log_debugsxp ("s_pkey", s_pkey);
	//print_sexp(s_pkey);

	/* Put DATA into a simplified S-expression.  */
	gcry_mpi_t gcry_data = gcry_mpi_new(0);
	size_t data_scanned_length;
	rc = gcry_mpi_scan(&gcry_data, GCRYMPI_FMT_USG, "00010203040506070809101112131415", 32, &data_scanned_length);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	printf("data_scanned_length: %i\n", data_scanned_length);
	//rc = gcry_sexp_build (&s_data, NULL, "%m", gcry_data);
	//unsigned char data_as_string [] = {'A', 'B', 0x00};
	size_t erroff;
	rc = gcry_sexp_build(&s_data, &erroff, "(data(flags pkcs1)(value %s))", "00010203040506070809101112131415");
	if(rc){
		fprintf (stderr, "Failure: %s/%s\n",
			gcry_strsource (rc),
			gcry_strerror (rc));
		printf("erroff: %i\n", erroff);
	}
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_log_debugsxp ("s_data", s_data);
	gcry_log_debugmpi ("gcry_data", gcry_data);
	//print_mpi(gcry_data);
	gcry_mpi_release(gcry_data);

	//gcry_error_t gcry_error = gcry_pk_encrypt(gcry_sexp_t *r_ciph, gcry_sexp_t data, gcry_sexp_t pkey);
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	if(rc){
		fprintf(stderr, "File: %s, Line: %i.\n", __FILE__, __LINE__);
		exit(-1);
	}
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	//print_sexp(s_ciph);
	gcry_log_debugsxp ("s_ciph", s_ciph);
	gcry_mpi_t result_as_mpi = get_mpi_from_sexp(s_ciph, "a", GCRYMPI_FMT_USG);
	gcry_sexp_release(s_ciph);
	gcry_log_debugmpi ("result_as_mpi", result_as_mpi);
	//print_mpi(result_as_mpi);
	gcry_mpi_release(result_as_mpi);

	return 0;
}
