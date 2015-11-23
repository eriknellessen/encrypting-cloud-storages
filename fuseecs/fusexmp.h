/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp
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

int xmp_getattr(const char *path, struct stat *stbuf);
int xmp_access(const char *path, int mask);
int xmp_readlink(const char *path, char *buf, size_t size);
int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi);
int xmp_mknod(const char *path, mode_t mode, dev_t rdev);
int xmp_mkdir(const char *path, mode_t mode);
int xmp_unlink(const char *path);
int xmp_rmdir(const char *path);
int xmp_symlink(const char *from, const char *to);
int xmp_rename(const char *from, const char *to);
int xmp_link(const char *from, const char *to);
int xmp_chmod(const char *path, mode_t mode);
int xmp_chown(const char *path, uid_t uid, gid_t gid);
int xmp_truncate(const char *path, off_t size);
#ifdef HAVE_UTIMENSAT
int xmp_utimens(const char *path, const struct timespec ts[2]);
#endif
int xmp_open(const char *path, struct fuse_file_info *fi);
int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi);
int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi);
int xmp_statfs(const char *path, struct statvfs *stbuf);
int xmp_release(const char *path, struct fuse_file_info *fi);
int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi);
#ifdef HAVE_POSIX_FALLOCATE
int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi);
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags);
int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size);
int xmp_listxattr(const char *path, char *list, size_t size);
int xmp_removexattr(const char *path, const char *name);
#endif /* HAVE_SETXATTR */
