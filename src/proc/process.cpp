#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cassert>
#include <fcntl.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>
#include <sys/sysctl.h>
#define _GNU_SOURCE
#include <sys/syscall.h>
#undef _GNU_SOURCE
#endif

#include "common.h"
#include "noah.h"
#include "vm.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/futex.h"


struct proc *proc;
_Thread_local struct task task;

DEFINE_SYSCALL(getpid)
{
  return proc->pid;
}

DEFINE_SYSCALL(exit, int, reason)
{
  if (task.clear_child_tid) {
    int zero = 0;
    if (copy_to_user(task.clear_child_tid, &zero, sizeof zero))
      return -LINUX_EFAULT;
    //do_futex_wake(task.clear_child_tid, 1);
  }
  destroy_vcpu();
  pthread_rwlock_wrlock(&proc->lock);
  if (proc->nr_tasks == 1) {
    _exit(reason);
  }
  else {
    proc->nr_tasks--;
    list_del(&task.head);
    pthread_rwlock_unlock(&proc->lock);
    pthread_exit(&reason);
  }
}

#ifdef _WIN32
DEFINE_SYSCALL(wait4, int, pid, gaddr_t, status_ptr, int, options, gaddr_t, rusage_ptr)
{
  // TODO: status, options, rusage
  auto find = vkern->procs->find(pid);
  if (find == vkern->procs->cend()) {
    return -LINUX_ECHILD;
  }
  auto proc = find->second;
  WaitForSingleObject(proc->platform.handle, INFINITE);
  return 0;
}
#endif
