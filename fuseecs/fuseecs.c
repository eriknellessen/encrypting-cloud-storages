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
#include "data_operations.h"
#include "gpg_operations.h"

//TODO: Dropbox knows about the existence of these files, but cannot read them. We need to remove these files
//from the lists, Dropbox gets from the list dir commands. Or we implement these files as virtual files.
const char *Forbidden_file_names[NUMBER_OF_FORBIDDEN_FILE_NAMES] = {PASSWORD_FILE_NAME, ENCFS_CONFIGURATION_FILE};

/* General TODO: Dropbox does not do the synchronisation automatically anymore. We can make it by choosing
 * stop synchronisation and then start synchronisation.
 */

enum Access_policy{DROPBOX, /*ENCFS,*/ USER};

long get_file_size(char *path){
	FILE *f = fopen(path, "r");
	if(f == NULL){
		fprintf(stderr, "Could not read file %s (when trying to get size).\n", path);
		exit(-1);
	}
	fseek(f, 0, SEEK_END);
	long return_value = ftell(f);
	fclose(f);
	return return_value;
}

//Creates empty encfs configuration file with the proper access rights. Creates random password and saves it in an encrypted file.
void create_encfs_directory(const char *encrypted_directory){
	//Debug
	printf("create_encfs_directory called. encrypted_directory: %s\n", encrypted_directory);
	
	//TODO: On the virtual machine, encfs aborts, because it can not read the configuration file, if we do it like that.
	/*
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
	*/
	
	//Create random password and encrypt it
	GET_RANDOM_PASSWORD(password)
	printf("password before encryption: %s\n", password);
	//We need to also sign the path. Otherwise, the storage provider could
	//put the same password file in all folders and we would only use one password for everything.
	/*
	 * Format: "/path/to/folder/encrypted/with/the/password\0x01password"
	 */
	SEPARATE_STRINGS(encrypted_directory, password, plain_text)
	//When in top folder, perform asymmetric encryption. Else, just put the password and path
	//in .password file and let Encfs encrypt it
	if(strcmp(encrypted_directory, ROOT_DIRECTORY) == 0){
		//Debug
		printf("In root directory, performing asymmetric encryption.\n");

		sign_and_encrypt(plain_text, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_directory, PASSWORD_FILE_NAME);
	} else {
		//Debug
		printf("Not in root directory. Writing password to file.\n");
		
		GET_FOLDER_NAME_ITERATIVELY(encrypted_directory, DECRYPT, decrypted_path)
		LOCAL_STR_CAT(decrypted_path, "../", one_folder_above_decrypted_path)
		STRIP_UPPER_DIRECTORIES_AND_SLASH(encrypted_directory, stripped_path)
		//Debug
		printf("Stripped path: %s.\n", stripped_path);
		
		LOCAL_STR_CAT(PASSWORD_FILE_NAME, stripped_path, password_file_with_stripped_path)
		free(stripped_path);
		LOCAL_STR_CAT(one_folder_above_decrypted_path, password_file_with_stripped_path, password_path)
		WRITE_FILE(password_path, plain_text)
	}
	
	//Debug
	printf("end of create_encfs_directory. encrypted_directory: %s\n", encrypted_directory);
}

void start_encfs(const char *encrypted_directory_maybe_without_slash, const char *mount_point_maybe_without_slash){
	//Debug
	printf("start_encfs called. encrypted_directory: %s, mount_point: %s\n", encrypted_directory_maybe_without_slash, mount_point_maybe_without_slash);
	
	APPEND_SLASH_IF_NECESSARY_REPEATABLE(encrypted_directory_maybe_without_slash, encrypted_directory)
	APPEND_SLASH_IF_NECESSARY_REPEATABLE(mount_point_maybe_without_slash, mount_point)
	
	//If the folder has not yet been initiated with encrypted password and so on, initiate it
	LOCAL_STR_CAT(encrypted_directory, ENCFS_CONFIGURATION_FILE, path_with_encfs_file)
	LOCAL_STR_CAT(path_with_encfs_file, OWN_PUBLIC_KEY_FINGERPRINT, path_with_encfs_file_and_own_fingerprint)
	LOCAL_STR_CAT(path_with_encfs_file_and_own_fingerprint, ENCRYPTED_FILE_ENDING, encrypted_encfs_file)
	if(access(encrypted_encfs_file, F_OK) == -1){
		create_encfs_directory(encrypted_directory);
	}
	
	//Folder has been created
	
	//If there is an encrypted version of the configuration file, decrypt it.
	//Decrypt data, check signature, check path
	if(access(encrypted_encfs_file, F_OK) == 0){
		LOCAL_STR_CAT(ENCFS_CONFIGURATION_FILE, OWN_PUBLIC_KEY_FINGERPRINT, encfs_configuration_file_with_fingerprint)
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_directory, encfs_configuration_file_with_fingerprint, encfs_configuration_data)
		printf("encfs configuration data after decryption: %s\n", encfs_configuration_data);
		//Write data to file
		WRITE_FILE(path_with_encfs_file, encfs_configuration_data)
		
		//Debug
		LOCAL_STR_CAT("/bin/bash -c \"cp ", encrypted_directory, cp_cmd_without_file)
		LOCAL_STR_CAT(cp_cmd_without_file, ENCFS_CONFIGURATION_FILE, cp_cmd_without_file_ending)
		LOCAL_STR_CAT(cp_cmd_without_file_ending, "{,.old}", cp_cmd_without_ending_quotation_mark)
		LOCAL_STR_CAT(cp_cmd_without_ending_quotation_mark, "\"", cp_cmd)
		if(system(cp_cmd)){
			fprintf(stderr, "Could not copy encfs configuration file with the following command: %s\n", cp_cmd);
			exit(-1);
		}
	}
	
	//Get decrypted password
	GET_PASSWORD(encrypted_directory, password)
	printf("password after decryption: %s\n", password);
	
	//Start encfs process
	//TODO: Giving the password in that form is not a good idea, as it is visible for everyone who can view processes via ps
	//Did that TODO. New TODO: Dropbox can still access the .password file. That is the case, because it accesses the encrypted
	//folder with our access rights. So to prevent Dropbox from reading the password file, we also need to change the read_file
	//function.
	//Create password file with the right access rights (so Dropbox can not access it)
	LOCAL_STR_CAT(encrypted_directory, PASSWORD_FILE_NAME, path_with_password_file)
	LOCAL_STR_CAT("touch ", path_with_password_file, touch_cmd)
	if(system(touch_cmd)){
		fprintf(stderr, "Could not touch password file.\n");
		exit(-1);
	}
	LOCAL_STR_CAT("chmod 600 ", path_with_password_file, chmod_cmd)
	if(system(chmod_cmd)){
		fprintf(stderr, "Could not chmod password file.\n");
		exit(-1);
	}
	WRITE_FILE(path_with_password_file, password)
	free(password);
	
	/*
	LOCAL_STR_CAT("echo ", password, echo_password_string)
	free(password);
	LOCAL_STR_CAT(echo_password_string, " | ", echo_password_string_with_pipe)
	LOCAL_STR_CAT(echo_password_string_with_pipe, ENCFS_COMMAND, cmd_without_encrypted_directory)
	LOCAL_STR_CAT(cmd_without_encrypted_directory, encrypted_directory, cmd_with_encrypted_directory)
	LOCAL_STR_CAT(cmd_with_encrypted_directory, " ", cmd_with_encrypted_directory_and_space)
	LOCAL_STR_CAT(cmd_with_encrypted_directory_and_space, mount_point, concatenated_cmd)
	printf("before popen.\n");
	printf("Executing the following command: %s\n", concatenated_cmd);
	//if(system(concatenated_cmd)){
	//	fprintf(stderr, "Error when executing encfs!\n");
	//	exit(-1);
	//}
	popen(concatenated_cmd, "r");
	*/
	
	LOCAL_STR_CAT(ENCFS_COMMAND, CAT_COMMAND, cmd_without_password_file)
	LOCAL_STR_CAT(cmd_without_password_file, path_with_password_file, cmd_with_password_file)
	LOCAL_STR_CAT(cmd_with_password_file, "\" ", cmd_with_password_file_and_quotas)
	LOCAL_STR_CAT(cmd_with_password_file_and_quotas, encrypted_directory, cmd_with_encrypted_directory)
	LOCAL_STR_CAT(cmd_with_encrypted_directory, " ", cmd_with_encrypted_directory_and_space)
	LOCAL_STR_CAT(cmd_with_encrypted_directory_and_space, mount_point, concatenated_cmd)
	printf("before popen.\n");
	printf("Executing the following command: %s\n", concatenated_cmd);
	//if(system(concatenated_cmd)){
	//	fprintf(stderr, "Error when executing encfs!\n");
	//	exit(-1);
	//}
	popen(concatenated_cmd, "r");
	//Endof Start encfs process
	
	//Debug: Check if encfs changed our configuration file.
	LOCAL_STR_CAT(path_with_encfs_file, ".old", path_with_old_encfs_file)
	if(access(path_with_old_encfs_file, F_OK) == 0){
		//Debug: Because there are problems with encfs on the virtual machine, we do not create the file before and use the second version.
		//while(get_file_size(path_with_encfs_file) == 0);
		while(access(path_with_encfs_file, F_OK) != 0 || get_file_size(path_with_encfs_file) == 0);
		LOCAL_STR_CAT("/bin/bash -c \"diff -u ", encrypted_directory, diff_cmd_without_file)
		LOCAL_STR_CAT(diff_cmd_without_file, ENCFS_CONFIGURATION_FILE, diff_cmd_without_file_ending)
		LOCAL_STR_CAT(diff_cmd_without_file_ending, "{,.old}", diff_cmd_without_ending_quotation_mark)
		LOCAL_STR_CAT(diff_cmd_without_ending_quotation_mark, "\"", diff_cmd)
		if(system(diff_cmd)){
			fprintf(stderr, "Encfs changed the configuration file!\n");
			exit(-1);
		}
	}
	
	//If there is no encrypted version of configuration file, create it.
	//TODO: Encfs sometimes does not like our decrypted config files. Not sure what the problem is.
	//Maybe this problem only occurs when there are still encfs processes running (noticed this once).
	if(access(encrypted_encfs_file, F_OK) != 0){
		//Wait for encfs to create the file
		//Debug: Because there are problems with encfs on the virtual machine, we do not create the file before and use the second version
		//while(get_file_size(path_with_encfs_file) == 0);
		while(access(path_with_encfs_file, F_OK) != 0 || get_file_size(path_with_encfs_file) == 0);
		//Read file
		READ_FILE(path_with_encfs_file, encfs_configuration_data)
		printf("Read the following encfs configuration data from file: %s\n", encfs_configuration_data);
		//Prepend path
		SEPARATE_STRINGS(encrypted_directory, encfs_configuration_data, path_and_encfs_configuration_data)
		//Encrypt the data and write to file
		sign_and_encrypt(path_and_encfs_configuration_data, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_directory, ENCFS_CONFIGURATION_FILE);
	}
	
	free(encrypted_directory);
	free(mount_point);
	
	//Debug
	printf("end of start_encfs. encrypted_directory: %s, mount_point: %s\n", encrypted_directory_maybe_without_slash, mount_point_maybe_without_slash);
}

void start_encfs_for_directory(char *encrypted_directory){
	//Debug
	printf("start_encfs_for_directory called. encrypted_directory: %s\n", encrypted_directory);
	
	//Start encfs for the correct folder.
	//Get correct directory name
	 if(strcmp(encrypted_directory, ROOT_DIRECTORY) == 0){
		//Debug
		printf("Calling start_encfs from start_encfs_for_directory.\n");
		
	 	start_encfs(encrypted_directory, DECRYPTED_DIRECTORY);
	 } else {
	 	GET_DECRYPTED_FOLDER_NAME_ITERATIVELY(encrypted_directory, decrypted_folder_name)
		//Debug
		printf("Calling start_encfs from start_encfs_for_directory.\n");
		
	 	start_encfs(encrypted_directory, decrypted_folder_name);
	 }
	
	struct dirent *m_dirent;
	
	DIR *m_dir = opendir(encrypted_directory);
	if(m_dir == NULL){
		fprintf(stderr, "Can't open %s\n", encrypted_directory);
		exit(-1);
	}
	
	while((m_dirent = readdir(m_dir)) != NULL){
		if(strcmp(m_dirent->d_name, ".") && strcmp(m_dirent->d_name, "..") && strcmp(m_dirent->d_name, DROPBOX_INTERNAL_FILES_DIRECTORY)){
			struct stat stbuf;
			APPEND_SLASH_IF_NECESSARY(encrypted_directory, path)
			LOCAL_STR_CAT(path, m_dirent->d_name, path_with_file)
			printf("start_encfs_for_directory: examining file %s\n", path_with_file);
			if(stat(path_with_file, &stbuf) == -1){
				fprintf(stderr, "Unable to stat file: %s\n", path_with_file) ;
				exit(-1);
			}

			if((stbuf.st_mode & S_IFMT ) == S_IFDIR){
				printf("start_encfs_for_directory: I think, this is a directory!\n");
				//Directory
				//Recursive call
				start_encfs_for_directory(path_with_file);
			}
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
	/*
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
	*/
	//Then it is the user
	return USER;
}

//Returns -1, if file name is in the list of forbidden file names
int check_forbidden_files(const char *path){
	int return_value = 0;
	STRIP_UPPER_DIRECTORIES_AND_SLASH(path, file_name)
	for(int i = 0; i < NUMBER_OF_FORBIDDEN_FILE_NAMES; i++){
		if(!strcmp(file_name, Forbidden_file_names[i])){
			return_value = -1;
			break;
		}
	}
	free(file_name);
	return return_value;
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
	int return_value;
	enum Access_policy ap = check_access(fuse_get_context());
	if(ap == DROPBOX){
		/* Case 1: Dropbox is trying to create a directory. Then we redirect to the encrypted folder.
		* We do not have to start encfs in the newly created folder. */
		if(path[0] == '/'){
			path = path + sizeof(char) * 1;
		}
		GET_RETURN_VALUE(ROOT_DIRECTORY, xmp_mkdir(CONCATENATED_PATH, mode))
	} else {
		/* Case 2: The user is trying to create a directory. Then we just write to the decrypted folder.
		* Afterwards, we start encfs in the newly created folder. */
		//Encfs will not take this way, it takes directly the way to the encrypted folder. So we have to do this in every case.
		//Create new folder in decrypted directory
		GET_RETURN_VALUE(DECRYPTED_DIRECTORY, xmp_mkdir(CONCATENATED_PATH, mode))
		
		//Now start encfs in the new encrypted folder, which encfs just created
		GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(path, path_to_new_encrypted_folder)
		//Check, if folder already exists at that point. If not, wait.
		while(access(path_to_new_encrypted_folder, F_OK) != 0);
		if(path[0] == '/'){
			path = path + sizeof(char) * 1;
		}
		LOCAL_STR_CAT(DECRYPTED_DIRECTORY, path, full_decrypted_path)
		//Debug
		printf("Calling start_encfs from ecs_mkdir.\n");
		
		start_encfs(path_to_new_encrypted_folder, full_decrypted_path);
	}

	return return_value;
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
	gpgme_check_version(NULL);
	start_encfs_for_directory(ROOT_DIRECTORY);
	umask(0);
	return fuse_main(argc, argv, &ecs_oper, NULL);
}
