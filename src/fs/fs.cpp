#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <sys/syslimits.h>
#endif
#endif
#ifdef _WIN32
#include <io.h>
#endif

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstdbool>
#include <cstring>
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

extern "C" {
#include "common.h"
#include "noah.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "fs.h"
}

#ifdef __APPLE__
int
resolve_path(const struct dir *parent, const char *name, int flags, struct path *path, int loop)
{
  struct fs *fs = &darwinfs;

  if (loop > LOOP_MAX)
    return -LINUX_ELOOP;

  struct dir dir = *parent;

  /* resolve mountpoints */
  if (*name == '/') {
    if (name[1] == '\0') {
      dir.fd = proc->fileinfo.rootfd;
      strcpy(path->subpath, ".");
      goto out;
    }
    if (strncmp(name, "/Users", sizeof "/Users" - 1) && strncmp(name, "/Volumes", sizeof "/Volumes" - 1) && strncmp(name, "/dev", sizeof "/dev" - 1) && strncmp(name, "/tmp", sizeof "/tmp" - 1) && strncmp(name, "/private", sizeof "/private" - 1)) {
      dir.fd = proc->fileinfo.rootfd;
      name++;
    }
  }

  /* resolve symlinks */
  char *sp = path->subpath;
  *sp = 0;
  const char *c = name;
  assert(*c);
  while (*c) {
    while (*c && *c != '/') {
      *sp++ = *c++;
    }
    *sp = 0;
    if ((flags & LOOKUP_NOFOLLOW) == 0) {
      // TODO: resolve symlinks
    }
    if (*c) {
      *sp++ = *c++;
    }
    *sp = 0;
  }

 out:
  path->fs = fs;
  path->dir = malloc(sizeof(struct dir));
  path->dir->fd = dir.fd;
  return 0;
}

int
vfs_grab_dir(int dirfd, const char *name, int flags, struct path *path)
{
  struct dir dir;

  if (flags & ~(LOOKUP_NOFOLLOW | LOOKUP_DIRECTORY)) {
    return -LINUX_EINVAL;
  }

  if (*name == 0) {
    return -LINUX_ENOENT;
  }

  if (dirfd == LINUX_AT_FDCWD) {
    dir.fd = AT_FDCWD;
  } else {
    dir.fd = dirfd;
    // if (!in_userfd(dir.fd)) {
    //   return -LINUX_EBADF;
    // }
  }
  return resolve_path(&dir, name, flags, path, 0);
}

void
vfs_ungrab_dir(struct path *path)
{
  free(path->dir);
}

static int
do_openat(int dirfd, const char *name, int flags, int mode)
{
  int lkflag = 0;
  if (flags & LINUX_O_NOFOLLOW) {
    lkflag |= LOOKUP_NOFOLLOW;
  }
  if (flags & LINUX_O_DIRECTORY) {
    lkflag |= LOOKUP_DIRECTORY;
  }

  struct path path;
  int r = vfs_grab_dir(dirfd, name, lkflag, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->openat(path.fs, path.dir, path.subpath, flags, mode);
  vfs_ungrab_dir(&path);
  return r;
}

int
do_close(struct fdtable *table, int fd)
{
  if (fd < table->start || fd >= table->start + table->size) {
    return -LINUX_EBADF;
  }
//   if (!test_fdbit(table, table->open_fds, fd)) {
//     return -LINUX_EBADF;
//   }
//   struct file *file = &table->files[fd - table->start];
//   assert(file);
  int n = syswrap(close(fd));
//   clear_fdbit(table, table->open_fds, fd);
//   clear_fdbit(table, table->cloexec_fds, fd);
  return n;
}

int
vkern_openat(int atdirfd, const char *name, int flags, int mode)
{
  int ret;

  pthread_rwlock_wrlock(&proc->fileinfo.fdtable_lock);
  int fd = do_openat(atdirfd, name, flags, mode);
  if (fd < 0) {
    ret = fd;
    goto out;
  }
  ret = fd;
//  ret = vkern_dup_fd(fd, flags & LINUX_O_CLOEXEC);
  close(fd);

out:
  pthread_rwlock_unlock(&proc->fileinfo.fdtable_lock);
  return ret;
}

int
vkern_open(const char *path, int l_flags, int mode)
{
  return vkern_openat(LINUX_AT_FDCWD, path, l_flags, mode);
}

int
vkern_close(int fd)
{
  pthread_rwlock_wrlock(&proc->fileinfo.fdtable_lock);
  int n = do_close(&proc->fileinfo.vkern_fdtable, fd);
  pthread_rwlock_unlock(&proc->fileinfo.fdtable_lock);
  return n;
}

#endif

extern "C" {

DEFINE_SYSCALL(read, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = reinterpret_cast<char *>(malloc(size));
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
  //struct iovec iov = { buf, size };
  // r = file->ops->readv(file, &iov, 1);
#ifdef _WIN32
  r = syswrap(_read(fd, buf, size));
#else
  r = syswrap(read(fd, buf, size));
#endif
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

}

extern "C" {

DEFINE_SYSCALL(write, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = reinterpret_cast<char *>(malloc(size));
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
  //struct iovec iov = { buf, size };
  // r =  file->ops->writev(file, &iov, 1);
#ifdef _WIN32
  r = syswrap(_write(fd, buf, size));
#else
  r = syswrap(write(fd, buf, size));
#endif
out:
  free(buf);
  return r;
}

}
