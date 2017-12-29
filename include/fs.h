#ifndef NOAH_FS_H
#define NOAH_FS_H

#include "types.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/fs.h"

#ifdef _WIN32
struct iovec {
  void *iov_base;
  size_t iov_len;
};
#else
#include <sys/uio.h>
#endif

#define LOOKUP_NOFOLLOW   0x0001
#define LOOKUP_DIRECTORY  0x0002
#define LOOKUP_CONTINUE   0x0004
#define LOOKUP_AUTOMOUNT  0x0008
#define LOOKUP_PARENT     0x0010
#define LOOKUP_REVAL      0x0020

#define LOOP_MAX 20

struct dir {
  int fd;
};

struct path {
  struct fs *fs;
  struct dir *dir;
  char subpath[LINUX_PATH_MAX];
};

struct file {
  struct file_operations *ops;
  int fd;
};

struct fs {
  struct fs_operations *ops;
};

struct fs_operations {
  int (*openat)(struct fs *fs, struct dir *dir, const char *path, int flags, int mode); /* TODO: return struct file * instaed of file descripter */
  int (*symlinkat)(struct fs *fs, const char *target, struct dir *dir, const char *name);
  int (*faccessat)(struct fs *fs, struct dir *dir, const char *path, int mode);
  int (*renameat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to);
  int (*linkat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to, int flags);
  int (*unlinkat)(struct fs *fs, struct dir *dir, const char *path, int flags);
  int (*readlinkat)(struct fs *fs, struct dir *dir, const char *path, char *buf, int bufsize);
  int (*mkdirat)(struct fs *fs, struct dir *dir, const char *path, int mode);
  /* inode operations */
  int (*fstatat)(struct fs *fs, struct dir *dir, const char *path, struct l_newstat *stat, int flags);
  int (*statfs)(struct fs *fs, struct dir *dir, const char *path, struct l_statfs *buf);
  int (*fchownat)(struct fs *fs, struct dir *dir, const char *path, l_uid_t uid, l_gid_t gid, int flags);
  int (*fchmodat)(struct fs *fs, struct dir *dir, const char *path, l_mode_t mode);
};

struct file_operations {
  int (*readv)(struct file *f, struct iovec *iov, size_t iovcnt);
  int (*writev)(struct file *f, const struct iovec *iov, size_t iovcnt);
  int (*close)(struct file *f);
  int (*ioctl)(struct file *f, int cmd, uint64_t val0);
  int (*lseek)(struct file *f, l_off_t offset, int whence);
  int (*getdents)(struct file *f, char *buf, uint count, bool is64);
  int (*fcntl)(struct file *f, unsigned int cmd, unsigned long arg);
  int (*fsync)(struct file *f);
  /* inode operations */
  int (*fstat)(struct file *f, struct l_newstat *stat);
  int (*fstatfs)(struct file *f, struct l_statfs *buf);
  int (*fchown)(struct file *f, l_uid_t uid, l_gid_t gid);
  int (*fchmod)(struct file *f, l_mode_t mode);
};


#ifdef __APPLE__

extern struct fs_operations dawinfs_ops;
extern struct fs darwinfs;

int darwinfs_openat(struct fs *fs, struct dir *dir, const char *path, int l_flags, int mode);
int darwinfs_close(struct file *file);
int darwinfs_writev(struct file *file, const struct iovec *iov, size_t iovcnt);
int darwinfs_readv(struct file *file, struct iovec *iov, size_t iovcnt);

#endif
#ifdef _WIN32
#define AT_FDCWD -100
#endif

#endif
