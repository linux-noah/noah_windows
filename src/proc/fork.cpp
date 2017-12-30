#include <cstdio>
#include <cstdlib>
#include <cassert>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <pthread.h>
#endif
#include <cstring>
#include <string>

extern "C" {
#include "common.h"
#include "noah.h"
#include "syscall.h"
#include "vmm.h"
#include "linux/common.h"
#include "linux/misc.h"
#include "linux/signal.h"
}


int
__do_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  return 0;
}

struct clone_thread_arg {
  unsigned long clone_flags;
  unsigned long newsp;
  gaddr_t parent_tid;
  gaddr_t child_tid;
  gaddr_t tls;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  //struct vcpu_snapshot vcpu_snapshot;
};

int
do_clone(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  return -LINUX_EINVAL;
}

extern "C" {

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

}
