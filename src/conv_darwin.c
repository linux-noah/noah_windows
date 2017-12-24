#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "linux/termios.h"
#include "linux/mman.h"

#include <unistd.h>
#include <termios.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>


int
native_to_linux_mprot(int darwin_prot)
{
  int linux_prot = 0;
  if (darwin_prot & PROT_READ)
    linux_prot |= LINUX_PROT_READ;
  if (darwin_prot & PROT_WRITE)
    linux_prot |= LINUX_PROT_WRITE;
  if (darwin_prot & PROT_EXEC)
    linux_prot |= LINUX_PROT_EXEC;
  return linux_prot;
}

int
linux_to_native_mprot(int linux_prot)
{
  int darwin_prot = 0;
  if (linux_prot & LINUX_PROT_READ)
    darwin_prot |= PROT_READ;
  if (linux_prot & LINUX_PROT_WRITE)
    darwin_prot |= PROT_WRITE;
  if (linux_prot & LINUX_PROT_EXEC)
    darwin_prot |= PROT_EXEC;
  return darwin_prot;
}

int
linux_to_native_o_flags(int l_flags)
{
  int ret = 0;
  if (l_flags & LINUX_O_PATH) {
    if (l_flags & LINUX_O_CLOEXEC)
      ret |= O_CLOEXEC;
    if (l_flags & LINUX_O_NOFOLLOW)
      ret |= O_SYMLINK;
    if (l_flags & LINUX_O_DIRECTORY)
      ret |= O_DIRECTORY;
    return ret;
  }
  switch (l_flags & LINUX_O_ACCMODE) {
  case LINUX_O_WRONLY:
    ret |= O_WRONLY;
    break;
  case LINUX_O_RDWR:
    ret |= O_RDWR;
    break;
  default:                      /* Note: LINUX_O_RDONLY == 0 */
    ret |= O_RDONLY;
  }
  if (l_flags & LINUX_O_NDELAY)
    ret |= O_NONBLOCK;
  if (l_flags & LINUX_O_APPEND)
    ret |= O_APPEND;
  if (l_flags & LINUX_O_SYNC)
    ret |= O_FSYNC;
  if (l_flags & LINUX_O_NONBLOCK)
    ret |= O_NONBLOCK;
  if (l_flags & LINUX_FASYNC)
    ret |= O_ASYNC;
  if (l_flags & LINUX_O_CREAT)
    ret |= O_CREAT;
  if (l_flags & LINUX_O_TRUNC)
    ret |= O_TRUNC;
  if (l_flags & LINUX_O_EXCL)
    ret |= O_EXCL;
  if (l_flags & LINUX_O_NOCTTY)
    ret |= O_NOCTTY;
  /* if (l_flags & LINUX_O_DIRECT) */
  /*   ret |= O_DIRECT; */
  if (l_flags & LINUX_O_NOFOLLOW)
    ret |= O_NOFOLLOW;
  if (l_flags & LINUX_O_DIRECTORY)
    ret |= O_DIRECTORY;

  return ret;
}
