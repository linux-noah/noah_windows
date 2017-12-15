#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>
#include <assert.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/futex.h"

#include <sys/sysctl.h>

#define _GNU_SOURCE
#include <sys/syscall.h>

struct proc proc;
_Thread_local struct task task;


int linux_to_darwin_waitopts(int options)
{
  int opts = 0;
  if (options & LINUX_WNOHANG) {
    opts |= WNOHANG;
    options &= ~LINUX_WNOHANG;
  }
  if (options & LINUX_WUNTRACED) {
    opts |= WUNTRACED;
    options &= ~LINUX_WUNTRACED;
  }
  if (options & LINUX_WCONTINUED) {
    opts |= WCONTINUED;
    options &= ~LINUX_WCONTINUED;
  }
  if (options & LINUX_WEXITED) {
    opts |= WEXITED;
    options &= ~LINUX_WEXITED;
  }
  if (options != 0) {
    warnk("unknown options given to wait4: 0x%x\n", options);
  }
  return opts;
}

