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
char *CONCATENATED_PATH = concat_path(path);\
int return_value = FUNCTION_CALL;\
free(CONCATENATED_PATH);\
return return_value;

const char Root_directory[] = "/tmp/decrypted";

char *concat_path(const char *path){
	char *concatenated_path = malloc(sizeof(char) * (strlen(Root_directory) + strlen(path) + 1));
	strcpy(concatenated_path, Root_directory);
	strcat(concatenated_path, path);
	return concatenated_path;
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
	return xmp_mkdir(path, mode);
}

static int ecs_unlink(const char *path)
{
	return xmp_unlink(path);
}

static int ecs_rmdir(const char *path)
{
	return xmp_rmdir(path);
}

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
	return xmp_chmod(path, mode);
}

static int ecs_chown(const char *path, uid_t uid, gid_t gid)
{
	return xmp_chown(path, uid, gid);
}

static int ecs_truncate(const char *path, off_t size)
{
	return xmp_truncate(path, size);
}

#ifdef HAVE_UTIMENSAT
static int ecs_utimens(const char *path, const struct timespec ts[2])
{
	return xmp_utimens(path, ts);
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
	return xmp_write(path, buf, size, offset, fi);
}

static int ecs_statfs(const char *path, struct statvfs *stbuf)
{
	return xmp_statfs(path, stbuf);
}

static int ecs_release(const char *path, struct fuse_file_info *fi)
{
	return xmp_release(path, fi);
}

static int ecs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	return xmp_fsync(path, isdatasync, fi);
}

#ifdef HAVE_POSIX_FALLOCATE
static int ecs_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	return xmp_fallocate(path, mode, offset, length, fi);
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int ecs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	return xmp_setxattr(path, name, value, size, flags);
}

static int ecs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	return xmp_getxattr(path, name, value, size);
}

static int ecs_listxattr(const char *path, char *list, size_t size)
{
	return xmp_listxattr(path, list, size);
}

static int ecs_removexattr(const char *path, const char *name)
{
	return xmp_removexattr(path, name);
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
