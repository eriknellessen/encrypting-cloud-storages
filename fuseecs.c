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

#define CONCATENATED_PATH concatenated_path
#define CHANGE_PATH(FUNCTION_CALL) printf(#FUNCTION_CALL": %s\n", path);\
enum Access_policy ap = check_access(fuse_get_context());\
printf("ap: %i\n", ap);\
printf("%s %d\n", __FILE__, __LINE__);\
struct fuse_context *fc = fuse_get_context();\
printf("path: %s\n", path);\
printf("uid: %i\n", fc->uid);\
if(ap == USER){\
	printf("%s %d\n", __FILE__, __LINE__);\
	char *CONCATENATED_PATH = concat_path(Decrypted_directory, path);\
	int return_value = FUNCTION_CALL;\
	printf("%s %d\n", __FILE__, __LINE__);\
	free(CONCATENATED_PATH);\
	printf("%s %d\n", __FILE__, __LINE__);\
	return return_value;\
}\
char *CONCATENATED_PATH = concat_path(Root_directory, path);\
printf("%s %d\n", __FILE__, __LINE__);\
int return_value = FUNCTION_CALL;\
printf("%s %d\n", __FILE__, __LINE__);\
free(CONCATENATED_PATH);\
printf("%s %d\n", __FILE__, __LINE__);\
return return_value;

#define ACCESS_USER_ID 1000
#define ROOT_USER_ID 0
#define ENCFS_USER_ID 1001

enum Access_policy{DROPBOX, ENCFS, USER};

const char Root_directory[] = "/tmp/encrypted";

const char Decrypted_directory[] = "/tmp/decrypted";

char *concat_path(const char *top_directory, const char *path){
	char *concatenated_path = malloc(sizeof(char) * (strlen(top_directory) + strlen(path) + 1));
	strcpy(concatenated_path, top_directory);
	strcat(concatenated_path, path);
	return concatenated_path;
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
		printf("Error when trying to snprintf.\n");
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
		printf("Failed to run command\n");
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
	umask(0);
	return fuse_main(argc, argv, &ecs_oper, NULL);
}
