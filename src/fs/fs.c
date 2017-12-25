/*-
 * Copyright (c) 2016 Yuichi Nishiwaki and Takaya Saeki
 * Copyright (c) 1994-1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "fs.h"

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
      dir.fd = proc.fileinfo.rootfd;
      strcpy(path->subpath, ".");
      goto out;
    }
    if (strncmp(name, "/Users", sizeof "/Users" - 1) && strncmp(name, "/Volumes", sizeof "/Volumes" - 1) && strncmp(name, "/dev", sizeof "/dev" - 1) && strncmp(name, "/tmp", sizeof "/tmp" - 1) && strncmp(name, "/private", sizeof "/private" - 1)) {
      dir.fd = proc.fileinfo.rootfd;
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

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd = do_openat(atdirfd, name, flags, mode);
  if (fd < 0) {
    ret = fd;
    goto out;
  }
  ret = fd;
//  ret = vkern_dup_fd(fd, flags & LINUX_O_CLOEXEC);
  close(fd);

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
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
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int n = do_close(&proc.fileinfo.vkern_fdtable, fd);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return n;
}

