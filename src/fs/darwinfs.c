#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "fs.h"

#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <mach-o/dyld.h>
#include <sys/syslimits.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct fs_operations darwinfs_ops = {
  darwinfs_openat,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};
struct fs darwinfs = {
  .ops = &darwinfs_ops,
};

int
darwinfs_openat(struct fs *fs, struct dir *dir, const char *path, int l_flags, int mode)
{
  int flags = linux_to_native_o_flags(l_flags);
  return syswrap(openat(dir->fd, path, flags, mode));
}

int
darwinfs_close(struct file *file)
{
  return syswrap(close(file->fd));
}

int
darwinfs_writev(struct file *file, const struct iovec *iov, size_t iovcnt)
{
  return syswrap(writev(file->fd, iov, iovcnt));
}

int
darwinfs_readv(struct file *file, struct iovec *iov, size_t iovcnt)
{
  return syswrap(readv(file->fd, iov, iovcnt));
}

DEFINE_SYSCALL(read, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);
  /*
  struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->readv == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  */
  struct iovec iov = { buf, size };
  // r = file->ops->readv(file, &iov, 1);
  r = syswrap(readv(fd, &iov, 1));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, r)) {
    r = -LINUX_EFAULT;
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(write, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);
  if (copy_from_user(buf, buf_ptr, size)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  /*struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->writev == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }*/
  struct iovec iov = { buf, size };
  // r =  file->ops->writev(file, &iov, 1);
  r = syswrap(writev(fd, &iov, 1));
out:
  free(buf);
  return r;
}
