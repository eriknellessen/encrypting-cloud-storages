#ifndef DATA_OPERATIONS_H
#define DATA_OPERATIONS_H

#include <string.h>
#include "configuration.h"

#define LOCAL_STR_CAT(START, END, RESULT) char RESULT[sizeof(char) * (strlen(START) + strlen(END) + 1)];\
strcpy(RESULT, START);\
strcat(RESULT, END);

#define CONCATENATED_PATH concatenated_path
#define GET_RETURN_VALUE(START_OF_PATH, FUNCTION_CALL) LOCAL_STR_CAT(START_OF_PATH, path, CONCATENATED_PATH)\
return_value = FUNCTION_CALL;
#define CHANGE_PATH(FUNCTION_CALL) printf(#FUNCTION_CALL": %s\n", path);\
enum Access_policy ap = check_access(fuse_get_context());\
printf("ap: %i\n", ap);\
printf("path: %s\n", path);\
printf("uid: %i\n", fuse_get_context()->uid);\
int return_value;\
if(ap == USER){\
	GET_RETURN_VALUE(DECRYPTED_DIRECTORY, FUNCTION_CALL)\
} else { \
	GET_RETURN_VALUE(ROOT_DIRECTORY, FUNCTION_CALL)\
}\
return return_value;

#define READ_FILE(PATH, RESULT) FILE *f = fopen(PATH, "r");\
if(f == NULL){\
	fprintf(stderr, "Could not read file %s.\n", PATH);\
	exit(-1);\
}\
fseek(f, 0, SEEK_END);\
long pos = ftell(f);\
fseek(f, 0, SEEK_SET);\
char RESULT[pos + 1];\
fread(RESULT, pos, 1, f);\
RESULT[pos] = 0;\
fclose(f);

#define WRITE_FILE(PATH, DATA) {\
FILE *f = fopen(PATH, "w");\
if(f == NULL){\
	fprintf(stderr, "Could not read file %s (when trying to write to it).\n", PATH);\
	exit(-1);\
}\
fputs(DATA, f);\
fclose(f);\
}

#define SEPARATE_STRINGS(FIRST, SECOND, RESULT) char separator_string[] = PATH_SEPARATOR_STRING;\
LOCAL_STR_CAT(FIRST, separator_string, first_string_with_separator)\
LOCAL_STR_CAT(first_string_with_separator, SECOND, RESULT) 

#endif