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

#define RUN_COMMAND_AND_GET_OUTPUT(COMMAND, RESULT) char *data = NULL;\
int pos = 0;\
{\
	FILE *pipe = popen(COMMAND, "r");\
	\
	char buffer[BUFFER_SIZE];\
	int size;\
	\
	if(pipe) {\
		while(fgets(buffer, BUFFER_SIZE, pipe) != NULL) {\
			size = strlen(buffer);\
			data = realloc(data, pos + size);\
			memcpy(&data[pos], buffer, size);\
			pos += size;\
		}\
	}\
	\
	if(pclose(pipe)){\
		fprintf(stderr, "Could not run command: %s.\n", COMMAND);\
		exit(-1);\
	}\
	\
}\
char RESULT[pos];\
memcpy(RESULT, data, pos);\
RESULT[pos - 1] = 0;\
free(data);

#define PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(LOCAL_STR, OUTER_VARIABLE) if(OUTER_VARIABLE != NULL){\
	free(OUTER_VARIABLE);\
}\
OUTER_VARIABLE = malloc(strlen(LOCAL_STR) + 1);\
strcpy(OUTER_VARIABLE, LOCAL_STR);

#define APPEND_SLASH_IF_NECESSARY(STRING, RESULT) int slash_needed = 0;\
if(STRING[strlen(STRING) - 1] != '/'){\
	slash_needed = 1;\
}\
char RESULT[strlen(STRING) + 1 + slash_needed];\
if(slash_needed){\
	strcpy(RESULT, STRING);\
	RESULT[strlen(STRING)] = '/';\
	RESULT[strlen(STRING) + 1] = 0;\
} else {\
	strcpy(RESULT, STRING);\
}

#define APPEND_SLASH_IF_NECESSARY_REPEATABLE(STRING, RESULT) char *RESULT = NULL;\
{\
	APPEND_SLASH_IF_NECESSARY(STRING, result)\
	PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, RESULT)\
}

#endif