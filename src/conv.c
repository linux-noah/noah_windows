#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "linux/termios.h"
#include "linux/signal.h"
#include "linux/mman.h"

#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/syslimits.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/mman.h>



int
darwin_to_linux_mprot(int darwin_prot)
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
linux_to_darwin_mprot(int linux_prot)
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
