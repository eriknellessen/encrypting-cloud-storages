char *rsa_encrypt(const char *plain_text, int plain_text_length, const char *public_key_fingerprint, size_t *result_length);
char *compute_hash_value_from_meta_data_lib_function(const char *meta_data, int meta_data_length, int *hash_value_length);
int get_hash_length_lib_function();