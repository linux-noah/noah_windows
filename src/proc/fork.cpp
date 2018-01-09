#include <cstdio>
#include <cstdlib>
#include <cassert>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <pthread.h>
#endif
#include <cstring>
#include <string>

#include "common.h"
#include "noah.h"
#include "syscall.h"
#include "vmm.h"
#include "linux/common.h"
#include "linux/misc.h"
#include "linux/signal.h"

int platform_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls);

int
__do_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
#ifdef _WIN32
  return platform_clone_process(clone_flags, newsp, parent_tid, child_tid, tls);
#else
  return -LINUX_EINVAL;
#endif
}

int
do_clone(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  int sigtype = clone_flags & 0xff;
  assert(sigtype == LINUX_SIGCHLD || sigtype == 0);

  clone_flags &= -0x100;
  unsigned long implemented = LINUX_CLONE_DETACHED | LINUX_CLONE_SETTLS | LINUX_CLONE_CHILD_SETTID | LINUX_CLONE_CHILD_CLEARTID | LINUX_CLONE_PARENT_SETTID;
  unsigned long needed = 0;
  if (clone_flags & LINUX_CLONE_THREAD) {
    int needed = LINUX_CLONE_VM | LINUX_CLONE_FS | LINUX_CLONE_FILES | LINUX_CLONE_SIGHAND | LINUX_CLONE_SYSVSEM;
    implemented |= needed;
  }
  if ((clone_flags & ~implemented) || (clone_flags & needed) != needed) {
    warnk("unsupported clone_flags: %lx\n", clone_flags);
    return -LINUX_EINVAL;
  }


  if (clone_flags & LINUX_CLONE_THREAD) {
    abort();
  } else {
    return __do_clone_process(clone_flags, newsp, parent_tid, child_tid, tls);
  }
}

DEFINE_SYSCALL(clone, unsigned long, clone_flags, unsigned long, newsp, gaddr_t, parent_tid, gaddr_t, child_tid, gaddr_t, tls)
{
  return do_clone(clone_flags, newsp, parent_tid, child_tid, tls);
}

DEFINE_SYSCALL(fork)
{
  return do_clone(LINUX_SIGCHLD, 0, 0, 0, 0);
}

DEFINE_SYSCALL(vfork)
{
  return do_clone(LINUX_SIGCHLD, 0, 0, 0, 0);
}
