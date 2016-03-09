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
#include <pthread.h>
#include <sched.h>
#include <signal.h>

#include "configuration.h"
#include "data_operations.h"
#include "gpg_operations.h"

const char *Forbidden_file_names[NUMBER_OF_FORBIDDEN_FILE_NAMES] = {PASSWORD_FILE_NAME, ENCFS_CONFIGURATION_FILE};

/* General TODO: Dropbox does not do the synchronisation automatically anymore. We can make it by choosing
 * stop synchronisation and then start synchronisation.
 * When we touch the file (as the dropbox user), e.g. touch Dropbox/9NY4zYsTpDh5hTS9644caqGa, Dropbox syncs
 * it afterwards. Touching the file directly, i.e. touch .ecs/encrypted/9NY4zYsTpDh5hTS9644caqGa does not work.
 * Even touching the file as the normal user, i.e. touch Dropbox/9NY4zYsTpDh5hTS9644caqGa works. Dropbox then
 * syncs the file. Anyhow, this command creates a file with the plaintext name 9NY4zYsTpDh5hTS9644caqGa, i.e.
 * a new encrypted file in .ecs/encrypted is created, which is not synced yet.
 */

/* General TODO: From Dropbox's point of view, is it possible to do a path traversal attack? I.e. reading the folder
 * Dropbox/../decrypted ? This would then be done with the user's privileges.
 */

/* General TODO: Dropbox does not synchronize files in directories like Dropbox/dir_1/subdirectory/
 * Even not after restarting Dropbox. Touching the subdirectory helps.
 */

enum Access_policy{DROPBOX, /*ENCFS,*/ USER};

void termination_handler(int signum){
	/* When we call encfs, it forks again and kills the process we created. That is why remembering our spawned
	 * pids does not help us kill our processes. It is also not possible to get the child processes via pgrep.
	 * Probably because the process is a zombie. So using pkill is probably the best way to do this.
	 */
	if(signum == SIGINT || signum == SIGTERM){
		//Kill our encfs processes
		LOCAL_STR_CAT(PKILL_COMMAND, ENCFS_COMMAND, pkill_cmd_with_encfs_cmd)
		//Remove trailing "
		pkill_cmd_with_encfs_cmd[strlen(pkill_cmd_with_encfs_cmd) - 1] = 0;
		LOCAL_STR_CAT(pkill_cmd_with_encfs_cmd, CAT_COMMAND, pkill_cmd_without_root_directory)
		LOCAL_STR_CAT(pkill_cmd_without_root_directory, ROOT_DIRECTORY, pkill_cmd_without_ending_quota)
		LOCAL_STR_CAT(pkill_cmd_without_ending_quota, "'", pkill_cmd)
		system(pkill_cmd);
		//Unmount MOUNT_POINT
		LOCAL_STR_CAT(FUSERUNMOUNT_COMMAND, MOUNTPOINT_DIRECTORY, fusermount_cmd)
		system(fusermount_cmd);

		exit(0);
	}
}

long get_file_size(const char *path){
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

void wait_until_file_is_created_and_has_content(const char *path){
	while(access(path, F_OK) != 0 || get_file_size(path) == 0){
		if(sched_yield()){
			fprintf(stderr, "pthread_yield returned error.\n");
			exit(-1);
		}
	}
	return;
}

//Creates empty encfs configuration file with the proper access rights. Creates random password and saves it in an encrypted file.
void create_encfs_directory(const char *encrypted_directory){
	//Debug
	printf("create_encfs_directory called. encrypted_directory: %s\n", encrypted_directory);
	
	//TODO: On the virtual machine, encfs aborts, because it can not read the configuration file, if we do it like that.
	//This should be solved by the forbidden files list/virtual files. But Dropbox is still able to read the encfs file
	//when reading the encrypted directory directly (not via the Dropbox folder). Is this a problem? It is not one, we
	//have to solve, but we maybe can. Sandboxing Dropbox, so it can not read the encrypted folder, would be sufficient.
	//chmod on the folder only is not sufficient, as it could still read files inside the folder. getfacl does the job.
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
		sign_and_encrypt(plain_text, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_directory, PASSWORD_FILE_NAME);
	} else {
		GET_FOLDER_NAME_ITERATIVELY(encrypted_directory, DECRYPT, decrypted_path)
		LOCAL_STR_CAT(decrypted_path, "../", one_folder_above_decrypted_path)
		STRIP_UPPER_DIRECTORIES_AND_SLASH(encrypted_directory, stripped_path)
		LOCAL_STR_CAT(PASSWORD_FILE_NAME, stripped_path, password_file_with_stripped_path)
		free(stripped_path);
		LOCAL_STR_CAT(one_folder_above_decrypted_path, password_file_with_stripped_path, password_path)
		WRITE_STRING_TO_FILE(password_path, plain_text)
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
		char *path_to_compare_to = NULL;
		STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_directory, encrypted_directory_name)
		if(directory_contains_authentic_file(encrypted_directory, DECRYPTED_FOLDER_NAME_FILE_NAME)){
			path_to_compare_to = encrypted_directory_name;
		} else {
			path_to_compare_to = encrypted_directory;
		}
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_directory, path_to_compare_to, encfs_configuration_file_with_fingerprint, encfs_configuration_data)
		//Write data to file
		WRITE_STRING_TO_FILE(path_with_encfs_file, encfs_configuration_data)
		
		/*
		//Debug
		LOCAL_STR_CAT("/bin/bash -c \"cp ", encrypted_directory, cp_cmd_without_file)
		LOCAL_STR_CAT(cp_cmd_without_file, ENCFS_CONFIGURATION_FILE, cp_cmd_without_file_ending)
		LOCAL_STR_CAT(cp_cmd_without_file_ending, "{,.old}", cp_cmd_without_ending_quotation_mark)
		LOCAL_STR_CAT(cp_cmd_without_ending_quotation_mark, "\"", cp_cmd)
		if(system(cp_cmd)){
			fprintf(stderr, "Could not copy encfs configuration file with the following command: %s\n", cp_cmd);
			exit(-1);
		}
		*/
	}
	
	//Get decrypted password
	GET_PASSWORD(encrypted_directory, password)
	printf("password after decryption: %s\n", password);
	
	//Start encfs process
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
	WRITE_STRING_TO_FILE(path_with_password_file, password)
	free(password);
	
	
	LOCAL_STR_CAT(ENCFS_COMMAND, CAT_COMMAND, cmd_without_password_file)
	LOCAL_STR_CAT(cmd_without_password_file, path_with_password_file, cmd_with_password_file)
	LOCAL_STR_CAT(cmd_with_password_file, "\" ", cmd_with_password_file_and_quotas)
	LOCAL_STR_CAT(cmd_with_password_file_and_quotas, encrypted_directory, cmd_with_encrypted_directory)
	LOCAL_STR_CAT(cmd_with_encrypted_directory, " ", cmd_with_encrypted_directory_and_space)
	LOCAL_STR_CAT(cmd_with_encrypted_directory_and_space, mount_point, concatenated_cmd)
	printf("before popen.\n");
	printf("Executing the following command: %s\n", concatenated_cmd);
	popen(concatenated_cmd, "r");

	/*
	//Debug: Check if encfs changed our configuration file.
	LOCAL_STR_CAT(path_with_encfs_file, ".old", path_with_old_encfs_file)
	if(access(path_with_old_encfs_file, F_OK) == 0){
		//Debug: Because there are problems with encfs on the virtual machine, we do not create the file before and use the second version.
		//while(get_file_size(path_with_encfs_file) == 0);
		wait_until_file_is_created_and_has_content(path_with_encfs_file);
		LOCAL_STR_CAT("/bin/bash -c \"diff -u ", encrypted_directory, diff_cmd_without_file)
		LOCAL_STR_CAT(diff_cmd_without_file, ENCFS_CONFIGURATION_FILE, diff_cmd_without_file_ending)
		LOCAL_STR_CAT(diff_cmd_without_file_ending, "{,.old}", diff_cmd_without_ending_quotation_mark)
		LOCAL_STR_CAT(diff_cmd_without_ending_quotation_mark, "\"", diff_cmd)
		if(system(diff_cmd)){
			fprintf(stderr, "Encfs changed the configuration file!\n");
			exit(-1);
		}
	}
	*/

	//If there is no encrypted version of configuration file, create it.
	//TODO: Encfs sometimes does not like our decrypted config files. Not sure what the problem is.
	//Maybe this problem only occurs when there are still encfs processes running (noticed this once).
	if(access(encrypted_encfs_file, F_OK) != 0){
		//Wait for encfs to create the file
		//Debug: Because there are problems with encfs on the virtual machine, we do not create the file before and use the second version
		//while(get_file_size(path_with_encfs_file) == 0);
		wait_until_file_is_created_and_has_content(path_with_encfs_file);
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

//encrypted_directory should be full path.
//Is called for encrypted_directory being a directory containing a DECRYPTED_FOLDER_NAME_FILE_NAME
void start_encfs_for_shared_directory(char *encrypted_directory, mode_t mode){
	//Debug
	printf("start_encfs_for_shared_directory started. encrypted_directory: %s\n", encrypted_directory);

	/* 1. Get decrypted folder name from encrypted folder name file in the folder.
	 * 2. Create that folder in the decrypted folder, if needed (encfs will create a corresponding folder in the encrypted folder)
	 * 3. Get encrypted folder name
	 * 4. Mark encrypted folder as not usable by placing a signed "do not use" file with the path in it.
	 * 5. Start encfs with path for the encrypted directory and the decrypted path for the mountpoint
	 */
	
	char *encrypted_folder_name = NULL;
	{
		STRIP_UPPER_DIRECTORIES_AND_ALL_SLASHES(encrypted_directory, encrypted_folder_name_local)
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(encrypted_folder_name_local, encrypted_folder_name)
	}
	char *decrypted_folder_name = NULL;
	{
		LOCAL_STR_CAT(DECRYPTED_FOLDER_NAME_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, decrypted_folder_name_file_with_fingerprint)
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_directory, encrypted_folder_name, decrypted_folder_name_file_with_fingerprint, decrypted_folder_name_local)
		//Debug
		printf("decrypted_folder_name_local: %s\n", decrypted_folder_name_local);
		free(encrypted_folder_name);
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(decrypted_folder_name_local, decrypted_folder_name)
	}
	//Debug
	printf("Step 1 completed. decrypted_folder_name: %s\n", decrypted_folder_name);

	printf("Step 2.1\n");
	//Get decrypted folder name
	//Strip last folder in path
	//Get the decrypted path
	//Append the decrypted folder name
	REMOVE_LAST_FOLDER(encrypted_directory, path_without_last_folder)
	printf("Step 2.2\n");
	char *decrypted_path_without_last_folder = NULL;
	{
		APPEND_SLASH_IF_NECESSARY(path_without_last_folder, path_without_last_folder_ending_on_slash)
		GET_DECRYPTED_FOLDER_NAME_ITERATIVELY(path_without_last_folder_ending_on_slash, decrypted_path_without_last_folder_local)
		PROPAGATE_LOCAL_STR_TO_OUTER_VARIABLE(decrypted_path_without_last_folder_local, decrypted_path_without_last_folder)
	}
	printf("Step 2.3\n");
	LOCAL_STR_CAT(decrypted_path_without_last_folder, decrypted_folder_name, decrypted_path)
	free(decrypted_path_without_last_folder);
	free(decrypted_folder_name);
	//Debug
	printf("decrypted path: %s\n", decrypted_path);
	if(access(decrypted_path, F_OK) != 0){
		if(xmp_mkdir(decrypted_path, mode)){
			fprintf(stderr, "Could not create dir: %s\n", decrypted_path);
			exit(-1);
		}
	}
	//Debug
	printf("Step 2 completed. decrypted_path: %s\n", decrypted_path);

	GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(decrypted_path, encrypted_path)
	//Debug
	printf("Step 3.1. encrypted_path: %s\n", encrypted_path);
	//Wait for encfs to create the folder
	wait_until_file_is_created_and_has_content(encrypted_path);
	//Debug
	printf("Step 3 completed. encrypted_path: %s\n", encrypted_path);

	LOCAL_STR_CAT(DO_NOT_DECRYPT_THIS_DIRECTORY_FILE_NAME, OWN_PUBLIC_KEY_FINGERPRINT, do_not_decrypt_file_name_with_fingerprint)
	LOCAL_STR_CAT(encrypted_path, do_not_decrypt_file_name_with_fingerprint, encrypted_path_with_file_name)
	LOCAL_STR_CAT(encrypted_path_with_file_name, ENCRYPTED_FILE_ENDING, path_to_do_not_decrypt_file)
	if(access(path_to_do_not_decrypt_file, F_OK) == 0){
		DECRYPT_DATA_AND_VERIFY_PATH(encrypted_path, encrypted_path, do_not_decrypt_file_name_with_fingerprint, result)
	} else {
		SEPARATE_STRINGS(encrypted_path, "", encrypted_path_with_separator)
		sign_and_encrypt(encrypted_path_with_separator, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_path, DO_NOT_DECRYPT_THIS_DIRECTORY_FILE_NAME);
	}
	//Debug
	printf("Step 4 completed.\n");

	start_encfs(encrypted_directory, decrypted_path);
	//Debug
	printf("Step 5 completed.\n");
	//Debug
	printf("start_encfs_for_shared_directory ended. encrypted_directory: %s\n", encrypted_directory);
}

void start_encfs_for_directory(char *encrypted_directory_maybe_without_slash){
	APPEND_SLASH_IF_NECESSARY(encrypted_directory_maybe_without_slash, encrypted_directory)
	//Debug
	printf("start_encfs_for_directory called. encrypted_directory: %s\n", encrypted_directory);
	
	if(directory_contains_authentic_file(encrypted_directory, DO_NOT_DECRYPT_THIS_DIRECTORY_FILE_NAME)){
		return;
	}
	
	if(directory_contains_authentic_file(encrypted_directory, DECRYPTED_FOLDER_NAME_FILE_NAME)){
		//mode does not matter, decrypted directory should be created by now
		start_encfs_for_shared_directory(encrypted_directory, 0744);
		return;
	}
	//Debug
	printf("start_encfs_for_directory: encrypted_directory %s is not a shared folder.\n", encrypted_directory);
	
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
			/* lstat is like stat, but does not try to resolve symbolic links.
			 * Symbolic links can not be resolved at this point, because they
			 * are still encrypted. See
			 * http://pubs.opengroup.org/onlinepubs/009695399/functions/lstat.html
			 */
			if(lstat(path_with_file, &stbuf) == -1){
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
	int i;
	for(i = 0; i < NUMBER_OF_FORBIDDEN_FILE_NAMES; i++){
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

static int ecs_revised_xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum Access_policy ap)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;
	while ((de = readdir(dp)) != NULL) {
		if(ap == USER || !check_forbidden_files(de->d_name)){
			struct stat st;
			memset(&st, 0, sizeof(st));
			st.st_ino = de->d_ino;
			st.st_mode = de->d_type << 12;
			if (filler(buf, de->d_name, &st, 0))
				break;
		}
	}

	closedir(dp);
	return 0;
}

static int ecs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	CHANGE_PATH(ecs_revised_xmp_readdir(CONCATENATED_PATH, buf, filler, offset, fi, check_access(fuse_get_context())))
}

static int ecs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	CHANGE_PATH(xmp_mknod(CONCATENATED_PATH, mode, rdev))
}

//TODO: How can we make sure, that the started encfs is killed when we kill the process?
static void *wait_for_dropbox_in_another_thread_and_start_encfs_for_shared_directory(void *relative_encrypted_directory_maybe_without_slash_void_pointer)
{
	char *relative_encrypted_directory_maybe_without_slash = (char *) relative_encrypted_directory_maybe_without_slash_void_pointer;
	APPEND_SLASH_IF_NECESSARY(relative_encrypted_directory_maybe_without_slash, relative_encrypted_directory)
	LOCAL_STR_CAT(ROOT_DIRECTORY, relative_encrypted_directory, encrypted_directory)
	LOCAL_STR_CAT(encrypted_directory, DECRYPTED_FOLDER_NAME_FILE_NAME, encrypted_directory_without_fingerprint)
	LOCAL_STR_CAT(encrypted_directory_without_fingerprint, OWN_PUBLIC_KEY_FINGERPRINT, encrypted_directory_without_file_ending)
	LOCAL_STR_CAT(encrypted_directory_without_file_ending, ENCRYPTED_FILE_ENDING, encrypted_directory_with_file_name)
	//TODO: Should we also wait, until Dropbox has completed writing to the file?
	wait_until_file_is_created_and_has_content(encrypted_directory_with_file_name);
	start_encfs_for_shared_directory(encrypted_directory, 0744);

	free(relative_encrypted_directory_maybe_without_slash_void_pointer);
	return NULL;
}

static int ecs_mkdir(const char *path, mode_t mode)
{
	int return_value;
	enum Access_policy ap = check_access(fuse_get_context());
	if(ap == DROPBOX){
		/* Case 1: Dropbox is trying to create a directory. Then we redirect to the encrypted folder.
		* We have to start encfs in the newly created folder, if it is not the DROPBOX_INTERNAL_FILES_DIRECTORY. */
		if(path[0] == '/'){
			path = path + sizeof(char) * 1;
		}
		GET_RETURN_VALUE(ROOT_DIRECTORY, xmp_mkdir(CONCATENATED_PATH, mode))
		if(return_value != 0){
			fprintf(stderr, "Could not create dir: %s\n", CONCATENATED_PATH);
			exit(-1);
		}

		if(strncmp(path, DROPBOX_INTERNAL_FILES_DIRECTORY, strlen(DROPBOX_INTERNAL_FILES_DIRECTORY)) != 0){
			/* TODO: Return, so Dropbox continues and puts files in the folder.
			 * Start a thread waiting for Dropbox to put the DECRYPTED_FOLDER_NAME_FILE_NAME
			 * file in the folder. When the file was created, this thread shall start
			 * the start_encfs_for_shared_directory function.
			 */

			char *not_const_path = malloc(sizeof(char) * (strlen(path) + 1));
			strcpy(not_const_path, path);
			//Not needed, just for compiler
			pthread_t thread;

			pthread_create(&thread, NULL, wait_for_dropbox_in_another_thread_and_start_encfs_for_shared_directory, not_const_path);
		}
	} else {
		/* Case 2: The user is trying to create a directory. Then we just write to the decrypted folder.
		* Afterwards, we start encfs in the newly created folder. */
		//Encfs will not take this way, it takes directly the way to the encrypted folder. So we have to do this in every case.
		//Create new folder in decrypted directory
		GET_RETURN_VALUE(DECRYPTED_DIRECTORY, xmp_mkdir(CONCATENATED_PATH, mode))
		
		//Now start encfs in the new encrypted folder, which encfs just created
		GET_ENCRYPTED_FOLDER_NAME_ITERATIVELY(path, path_to_new_encrypted_folder)
		//Check, if folder already exists at that point. If not, wait.
		wait_until_file_is_created_and_has_content(path_to_new_encrypted_folder);
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

/* TODO: Symbolic linking only works when we are already in the Dropbox folder.
 * ln -s Dropbox/dir_1 Dropbox/dir_3 leads to
 * Dropbox/dir_3 -> /home/destroyer/.ecs/decrypted/Dropbox/dir_1 (the "Dropbox"
 * should not exist between "decrypted" and "dir_1"). Besides, it would be
 * better not to show the decrypted folder in the path, but the Dropbox folder.
 * Dropbox does not upload our symbolic links. Maybe, because it cannot resolve
 * them?
 */
static int ecs_symlink(const char *from, const char *to)
{
	CHANGE_BOTH_PATHS(xmp_symlink(CONCATENATED_FROM, CONCATENATED_TO))
}

static int ecs_rename(const char *from, const char *to)
{
	CHANGE_BOTH_PATHS(xmp_rename(CONCATENATED_FROM, CONCATENATED_TO))
}

static int ecs_link(const char *from, const char *to)
{
	CHANGE_BOTH_PATHS(xmp_link(CONCATENATED_FROM, CONCATENATED_TO))
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
	//See http://www.gnu.org/software/libc/manual/html_node/Sigaction-Function-Example.html
	struct sigaction new_action;
	/* Set up the structure to specify the new action. */
	new_action.sa_handler = termination_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, &new_action, NULL);
	sigaction(SIGTERM, &new_action, NULL);
	
	gpgme_check_version(NULL);
	start_encfs_for_directory(ROOT_DIRECTORY);
	umask(0);
	return fuse_main(argc, argv, &ecs_oper, NULL);
}
