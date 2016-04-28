#ifndef DATA_OPERATIONS_H
#define DATA_OPERATIONS_H

#include <string.h>
#include "configuration.h"

#define NUMBER_OF_FORBIDDEN_FILE_NAMES 2
extern const char *Forbidden_file_names[];

#define STRING 0
#define BINARY 1

#define LOCAL_STR_CAT(START, END, RESULT) char RESULT[sizeof(char) * (strlen(START) + strlen(END) + 1)];\
	strcpy(RESULT, START);\
	strcat(RESULT, END);

#define CONCATENATED_PATH concatenated_path
#define GET_RETURN_VALUE(START_OF_PATH, FUNCTION_CALL) LOCAL_STR_CAT(START_OF_PATH, path, CONCATENATED_PATH)\
	return_value = FUNCTION_CALL;
#define CHANGE_PATH(FUNCTION_CALL) enum Access_policy ap = check_access(fuse_get_context());\
	int return_value;\
	if(ap == USER){\
		GET_RETURN_VALUE(DECRYPTED_DIRECTORY, FUNCTION_CALL)\
	} else { \
		if(check_forbidden_files(path) == -1){\
			return -1;\
		} else {\
			GET_RETURN_VALUE(ROOT_DIRECTORY, FUNCTION_CALL)\
		}\
	}\
	return return_value;

#define CONCATENATED_FROM concatenated_from
#define CONCATENATED_TO concatenated_to
#define GET_RETURN_VALUE_TWO_PATHS(START_OF_PATH, FUNCTION_CALL) LOCAL_STR_CAT(START_OF_PATH, from, CONCATENATED_FROM)\
	LOCAL_STR_CAT(START_OF_PATH, to, CONCATENATED_TO)\
	return_value = FUNCTION_CALL;
#define CHANGE_BOTH_PATHS(FUNCTION_CALL) enum Access_policy ap = check_access(fuse_get_context());\
	int return_value;\
	if(ap == USER){\
		GET_RETURN_VALUE_TWO_PATHS(DECRYPTED_DIRECTORY, FUNCTION_CALL)\
	} else { \
		if(check_forbidden_files(from) == -1 || check_forbidden_files(to) == -1)\
			return -1;\
		else {\
			GET_RETURN_VALUE_TWO_PATHS(ROOT_DIRECTORY, FUNCTION_CALL)\
		}\
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

#define WRITE_FILE(MODE, PATH, DATA, LENGTH) {\
	FILE *f = fopen(PATH, "w");\
	if(f == NULL){\
		fprintf(stderr, "Could not read file %s (when trying to write to it).\n", PATH);\
		exit(-1);\
	}\
	if(MODE == STRING)\
		fputs(DATA, f);\
	else {\
		if(fwrite(DATA, 1, LENGTH, f) != LENGTH){\
			fprintf(stderr, "Could not write data to file %s.\n", PATH);\
			fclose(f);\
			exit(-1);\
		}\
	}\
	fclose(f);\
}

#define WRITE_STRING_TO_FILE(PATH, DATA) {\
	WRITE_FILE(STRING, PATH, DATA, 0)\
}

#define WRITE_BINARY_DATA_TO_FILE(PATH, DATA, LENGTH) {\
	WRITE_FILE(BINARY, PATH, DATA, LENGTH)\
}

#define SEPARATE_STRINGS(FIRST, SECOND, RESULT) char separator_string[] = PATH_SEPARATOR_STRING;\
	LOCAL_STR_CAT(FIRST, separator_string, first_string_with_separator)\
	LOCAL_STR_CAT(first_string_with_separator, SECOND, RESULT)

/* End might be binary data, so length is needed */\
#define UNSEPARATE_STRINGS(DATA, DATA_LENGTH, BEGINNING, END, END_LENGTH) size_t end_of_beginning;\
	{\
		char *end_of_beginning_string = strchr(DATA, PATH_SEPARATOR);\
		end_of_beginning = end_of_beginning_string - DATA;\
	}\
	char BEGINNING[end_of_beginning + 1];\
	strncpy(BEGINNING, DATA, end_of_beginning);\
	BEGINNING[end_of_beginning] = 0;\
	/* TODO: Is this a bug? Was: data_length = strlen(DATA - (end_of_path + 1));\*/\
	int END_LENGTH = DATA_LENGTH - strlen(BEGINNING);\
	char END[END_LENGTH + 1];\
	memcpy(END, DATA + end_of_beginning + 1, END_LENGTH);\
	/* Attention: END might be binary data, can not always be treated as string afterwards. */\
	END[END_LENGTH] = 0;

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
	strcpy(OUTER_VARIABLE, LOCAL_STR);\

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

#define STRIP_UPPER_DIRECTORIES_AND_SLASH(MAYBE_CONST_PATH, RESULT) char *RESULT = NULL;\
	{\
		char not_const_path[strlen(MAYBE_CONST_PATH) + 1];\
		strcpy(not_const_path, MAYBE_CONST_PATH);\
		char *return_value = NULL;\
		char *end_string;\
		char *next_folder = strtok_r(not_const_path, "/", &end_string);\
		while(next_folder != NULL && strlen(next_folder) > 0){\
			return_value = next_folder;\
			next_folder = strtok_r(NULL, "/", &end_string);\
		}\
		if(return_value == NULL){\
			if(not_const_path[0] == '/'){\
				return_value = not_const_path + 1;\
			} else {\
				return_value = not_const_path;\
			}\
		}\
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(return_value, RESULT)\
	}

#define REMOVE_SLASH_IF_NECESSARY(STRING, RESULT) int remove_slash = 0;\
	if(STRING[strlen(STRING) - 1] == '/'){\
		remove_slash = 1;\
	}\
	char RESULT[strlen(STRING) + 1 - remove_slash];\
	if(remove_slash){\
		strncpy(RESULT, STRING, strlen(STRING) - 1);\
	} else {\
		strcpy(RESULT, STRING);\
	}

#define REMOVE_SLASH_IF_NECESSARY_REPEATABLE(STRING, RESULT) char *RESULT = NULL;\
	{\
		REMOVE_SLASH_IF_NECESSARY(STRING, result)\
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(result, RESULT)\
	}

#define STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(PATH, RESULT) STRIP_UPPER_DIRECTORIES_AND_SLASH(PATH, folder_name_maybe_with_ending_slash)\
	REMOVE_SLASH_IF_NECESSARY(folder_name_maybe_with_ending_slash, RESULT)\
	free(folder_name_maybe_with_ending_slash);

#define REMOVE_LAST_FOLDER(PATH, RESULT) REMOVE_SLASH_IF_NECESSARY(PATH, path_without_ending_slash)\
	char *end_of_result = strrchr(path_without_ending_slash, '/');\
	int length_of_result = end_of_result - path_without_ending_slash + 1;\
	char RESULT[length_of_result];\
	strncpy(RESULT, path_without_ending_slash, length_of_result - 1);\
	RESULT[length_of_result - 1] = 0;

#define SUBSTITUTE_DECRYPTED_DIRECTORY_WITH_MOUNTPOINT_DIRECTORY(PATH, RESULT) char RESULT[strlen(PATH) - strlen(DECRYPTED_DIRECTORY) + strlen(MOUNTPOINT_DIRECTORY)];\
	memcpy(RESULT, MOUNTPOINT_DIRECTORY, strlen(MOUNTPOINT_DIRECTORY));\
	strcpy(RESULT + strlen(MOUNTPOINT_DIRECTORY), PATH + strlen(DECRYPTED_DIRECTORY));

#endif