/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fuseecs.c `pkg-config fuse --cflags --libs` -o fuseecs
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "fusexmp.h"
#include <stdlib.h>
#include <gpgme.h>

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

#define GET_DECRYPTED_FOLDER_NAME(DIRECTORY) encfsctl decode --extpass="echo password" DIRECTORY

#define GET_RANDOM_PASSWORD(RESULT) char *get_random_password_data = NULL;\
{\
	LOCAL_STR_CAT(MAKEPASSWD_COMMAND, PASSWORD_LENGTH_STRING, cmd)\
	FILE *pipe = popen(cmd, "r");\
	\
	char buffer[BUFFER_SIZE];\
	int size;\
	int pos = 0;\
	\
	if(pipe) {\
		while(fgets(buffer, BUFFER_SIZE, pipe) != NULL) {\
			size = strlen(buffer);\
			get_random_password_data = realloc(get_random_password_data, pos + size);\
			memcpy(&get_random_password_data[pos], buffer, size);\
			pos += size;\
		}\
	}\
	\
	if(pclose(pipe)){\
		fprintf(stderr, "Could not generate password.\n");\
		exit(-1);\
	}\
	\
}\
char RESULT[strlen(get_random_password_data + 1)];\
strcpy(RESULT, get_random_password_data);\
free(get_random_password_data);

#define DECRYPT_AND_VERIFY(PATH, RESULT) char *plain_text;\
size_t length;\
{\
	gpgme_ctx_t gpgme_ctx;\
	if(gpgme_new(&gpgme_ctx) != GPG_ERR_NO_ERROR){\
		fprintf(stderr, "Could not create gpg context.\n");\
		exit(-1);\
	}\
	gpgme_data_t gpgme_encrypted_data;\
	if(gpgme_data_new_from_file(&gpgme_encrypted_data, PATH, 1) != GPG_ERR_NO_ERROR){\
		fprintf(stderr, "Could not read encrypted data from file %s.\n", PATH);\
		exit(-1);\
	}\
	gpgme_data_t gpgme_decrypted_data;\
	if(gpgme_data_new(&gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\
		fprintf(stderr, "Could not read encrypted data from file %s.\n", PATH);\
		exit(-1);\
	}\
	if(gpgme_op_decrypt_verify(gpgme_ctx, gpgme_encrypted_data, gpgme_decrypted_data) != GPG_ERR_NO_ERROR){\
		fprintf(stderr, "Could not decrypt and verify file %s.\n", PATH);\
		exit(-1);\
	}\
	gpgme_data_release(gpgme_encrypted_data);\
	gpgme_release(gpgme_ctx);\
	\
	plain_text = gpgme_data_release_and_get_mem(gpgme_decrypted_data, &length);\
}\
char RESULT[length + 1];\
if(memcpy(RESULT, plain_text, length) != RESULT){\
	fprintf(stderr, "Could not copy decrypted data.\n");\
	exit(-1);\
}\
RESULT[length] = 0;\
gpgme_free(plain_text);

enum Access_policy{DROPBOX, ENCFS, USER};

//gpg2 --sign --local-user A6506F46 --encrypt -r A6506F46 --output xxx.txt.gpg xxx.txt
void sign_and_encrypt(const char *data, const char *public_key_fingerprint, const char *path, const char *file_name){
	LOCAL_STR_CAT("echo ", data, cmd1)
	LOCAL_STR_CAT(cmd1, " | ", cmd2)
	LOCAL_STR_CAT(cmd2, GPG_SIGN_COMMAND, cmd3)
	LOCAL_STR_CAT(cmd3, OWN_PUBLIC_KEY_FINGERPRINT, cmd4)
	LOCAL_STR_CAT(cmd4, GPG_ENCRYPTION_OPTION, cmd5)
	LOCAL_STR_CAT(cmd5, OWN_PUBLIC_KEY_FINGERPRINT, cmd6)
	LOCAL_STR_CAT(cmd6, GPG_OUTPUT_OPTION, cmd7)
	LOCAL_STR_CAT(cmd7, file_name, cmd8)
	LOCAL_STR_CAT(cmd8, ENCRYPTED_FILE_ENDING, cmd9)
	LOCAL_STR_CAT(cmd9, " ", cmd10)
	LOCAL_STR_CAT(cmd10, file_name, concatenated_cmd)
	
	//Debug
	printf(concatenated_cmd);
	
	if(system(concatenated_cmd)){
		fprintf(stderr, "Could not sign and encrypt data.\n");
		exit(-1);
	}
}

void create_encfs_directory(const char *encrypted_directory){
	//Create configuration file with the right access rights (so Dropbox can not access it)
	LOCAL_STR_CAT(encrypted_directory, ENCFS_CONFIGURATION_FILE, path_with_file)
	LOCAL_STR_CAT("touch ", path_with_file, touch_cmd)
	if(system(touch_cmd)){
		fprintf(stderr, "Could not touch encfs configuration file.\n");
		exit(-1);
	}
	LOCAL_STR_CAT("chmod 600 ", path_with_file, chmod_cmd)
	if(system(chmod_cmd)){
		fprintf(stderr, "Could not chmod encfs configuration file.\n");
		exit(-1);
	}
	
	//Create random password and encrypt it
	GET_RANDOM_PASSWORD(password)
	//TODO: We need to also sign the fingerprint and the path. Otherwise, the storage provider could
	//put the same password file in all folders.
	sign_and_encrypt(password, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_directory, PASSWORD_FILE_NAME);
}

void start_encfs(const char *encrypted_directory, const char *mount_point){
	//If the folder has not yet been initiated with encrypted password and so on
	//(Check signature of password file)
	create_encfs_directory(encrypted_directory);
	
	//If the folder has already been created
	//Get decrypted password
	LOCAL_STR_CAT(encrypted_directory, PASSWORD_FILE_NAME, path_without_file_ending)
	LOCAL_STR_CAT(path_without_file_ending, ENCRYPTED_FILE_ENDING, path_with_file_ending)
	DECRYPT_AND_VERIFY(path_with_file_ending, password)
	//TODO: If there is an encrypted version of the configuration file, decrypt it.
	LOCAL_STR_CAT("echo ", password, echo_password_string)
	LOCAL_STR_CAT(echo_password_string, " | ", echo_password_string_with_pipe)
	LOCAL_STR_CAT(echo_password_string_with_pipe, ENCFS_COMMAND, cmd_without_encrypted_directory)
	LOCAL_STR_CAT(cmd_without_encrypted_directory, encrypted_directory, cmd_with_encrypted_directory)
	LOCAL_STR_CAT(cmd_with_encrypted_directory, " ", cmd_with_encrypted_directory_and_space)
	LOCAL_STR_CAT(cmd_with_encrypted_directory_and_space, mount_point, concatenated_cmd)
	popen(concatenated_cmd, "r");
	
	//TODO: If there is no encrypted version of configuration file, create it.
}

void start_encfs_for_directory(char *dir){
	//Start encfs for the correct folder.
	//Get correct directory name
	/*
	 * if(strcmp(dir, ROOT_DIRECTORY) == 0){
	 * 	start_encfs(dir, DECRYPTED_DIRECTORY);
	 * } else {
	 * 	GET_DECRYPTED_FOLDER_NAME(dir)
	 * 	start_encfs(dir, decrypted_folder_name);
	 * }
	*/
	struct dirent *m_dirent;
	
	DIR *m_dir = opendir(dir);
	if(m_dir == NULL){
		fprintf(stderr, "Can't open %s\n", dir);
		exit(-1);
	}
	
	while((m_dirent = readdir(m_dir)) != NULL){
		struct stat stbuf;
		LOCAL_STR_CAT(dir,"/", path)
		LOCAL_STR_CAT(path, m_dirent->d_name, path_with_file)
		if(stat(path_with_file, &stbuf) == -1){
			fprintf(stderr, "Unable to stat file: %s\n",path_with_file) ;
			exit(-1);
		}

		if((stbuf.st_mode & S_IFMT ) == S_IFDIR){
			//Directory
			//Recursive call
			start_encfs_for_directory(path_with_file);
		}
	}
}

enum Access_policy check_access(struct fuse_context *fc){
	/*switch(fc->uid){
		case ROOT_USER_ID:
		case ACCESS_USER_ID: return USER;
		case ENCFS_USER_ID: return ENCFS;
		default: return DROPBOX;
	}*/
	
	//Check if it is another user than the permitted one
	if(fc->uid != ACCESS_USER_ID && fc->uid != ROOT_USER_ID)
		return DROPBOX;
	
	//Check if it is EncFS
	//Build command to get the command name of the process
	char pid[10];
	int bytes_written = snprintf(pid, sizeof(pid), "%d", fc->pid);
	printf("%s\n", pid);
	if(bytes_written < 0 || bytes_written > sizeof(pid)){
		fprintf(stderr, "Error when trying to snprintf.\n");
		exit(1);
	}
	char begin_of_ps_cmd[] = "ps -o command ch --pid ";
	char concatenated_cmd[sizeof(begin_of_ps_cmd) + sizeof(pid)];
	strcpy(concatenated_cmd, begin_of_ps_cmd);
	strcat(concatenated_cmd, pid);
	//Start the command and get the result
	// Open the command for reading.
	FILE *fp = popen(concatenated_cmd, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to run command\n");
		exit(1);
	}
	// Read the first 5 signs of the output
	char buf[6];
	if(fgets(buf, sizeof(buf), fp) != NULL) {
		pclose(fp);
		printf("%s\n", buf);
		printf("%i\n", sizeof(buf) - 1);
		if(strcmp(buf, "encfs") == 0){
			return ENCFS;
		}
	}
	//Then it is the user
	return USER;
}

static int ecs_getattr(const char *path, struct stat *stbuf)
{
	CHANGE_PATH(xmp_getattr(CONCATENATED_PATH, stbuf))
}

static int ecs_access(const char *path, int mask)
{
	CHANGE_PATH(xmp_access(CONCATENATED_PATH, mask))
}

static int ecs_readlink(const char *path, char *buf, size_t size)
{
	CHANGE_PATH(xmp_readlink(CONCATENATED_PATH, buf, size))
}

static int ecs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_readdir(CONCATENATED_PATH, buf, filler, offset, fi))
}

static int ecs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	CHANGE_PATH(xmp_mknod(CONCATENATED_PATH, mode, rdev))
}

static int ecs_mkdir(const char *path, mode_t mode)
{
	CHANGE_PATH(xmp_mkdir(CONCATENATED_PATH, mode))
}

static int ecs_unlink(const char *path)
{
	CHANGE_PATH(xmp_unlink(CONCATENATED_PATH))
}

static int ecs_rmdir(const char *path)
{
	CHANGE_PATH(xmp_rmdir(CONCATENATED_PATH))
}

//TODO: These three have to be treated in another way than CHANGE_PATH
static int ecs_symlink(const char *from, const char *to)
{
	return xmp_symlink(from, to);
}

static int ecs_rename(const char *from, const char *to)
{
	return xmp_rename(from, to);
}

static int ecs_link(const char *from, const char *to)
{
	return xmp_link(from, to);
}

static int ecs_chmod(const char *path, mode_t mode)
{
	CHANGE_PATH(xmp_chmod(CONCATENATED_PATH, mode))
}

static int ecs_chown(const char *path, uid_t uid, gid_t gid)
{
	CHANGE_PATH(xmp_chown(CONCATENATED_PATH, uid, gid))
}

static int ecs_truncate(const char *path, off_t size)
{
	CHANGE_PATH(xmp_truncate(CONCATENATED_PATH, size))
}

#ifdef HAVE_UTIMENSAT
static int ecs_utimens(const char *path, const struct timespec ts[2])
{
	CHANGE_PATH(xmp_utimens(CONCATENATED_PATH, ts))
}
#endif

static int ecs_open(const char *path, struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_open(CONCATENATED_PATH, fi))
}

static int ecs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_read(CONCATENATED_PATH, buf, size, offset, fi))
}

static int ecs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_write(CONCATENATED_PATH, buf, size, offset, fi))
}

static int ecs_statfs(const char *path, struct statvfs *stbuf)
{
	CHANGE_PATH(xmp_statfs(CONCATENATED_PATH, stbuf))
}

static int ecs_release(const char *path, struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_release(CONCATENATED_PATH, fi))
}

static int ecs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_fsync(CONCATENATED_PATH, isdatasync, fi))
}

#ifdef HAVE_POSIX_FALLOCATE
static int ecs_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	CHANGE_PATH(xmp_fallocate(CONCATENATED_PATH, mode, offset, length, fi))
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int ecs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	CHANGE_PATH(xmp_setxattr(CONCATENATED_PATH, name, value, size, flags))
}

static int ecs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	CHANGE_PATH(xmp_getxattr(CONCATENATED_PATH, name, value, size))
}

static int ecs_listxattr(const char *path, char *list, size_t size)
{
	CHANGE_PATH(xmp_listxattr(CONCATENATED_PATH, list, size))
}

static int ecs_removexattr(const char *path, const char *name)
{
	CHANGE_PATH(xmp_removexattr(CONCATENATED_PATH, name))
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations ecs_oper = {
	.getattr	= ecs_getattr,
	.access		= ecs_access,
	.readlink	= ecs_readlink,
	.readdir	= ecs_readdir,
	.mknod		= ecs_mknod,
	.mkdir		= ecs_mkdir,
	.symlink	= ecs_symlink,
	.unlink		= ecs_unlink,
	.rmdir		= ecs_rmdir,
	.rename		= ecs_rename,
	.link		= ecs_link,
	.chmod		= ecs_chmod,
	.chown		= ecs_chown,
	.truncate	= ecs_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= ecs_utimens,
#endif
	.open		= ecs_open,
	.read		= ecs_read,
	.write		= ecs_write,
	.statfs		= ecs_statfs,
	.release	= ecs_release,
	.fsync		= ecs_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= ecs_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= ecs_setxattr,
	.getxattr	= ecs_getxattr,
	.listxattr	= ecs_listxattr,
	.removexattr	= ecs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	start_encfs(ROOT_DIRECTORY, DECRYPTED_DIRECTORY);
	umask(0);
	return fuse_main(argc, argv, &ecs_oper, NULL);
}
