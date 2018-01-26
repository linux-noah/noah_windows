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

DEFINE_SYSCALL(exit_group, int, reason)
{
  _exit(reason);
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

struct utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

DEFINE_SYSCALL(uname, gaddr_t, buf_ptr)
{
  struct utsname buf;

  strncpy(buf.sysname, "Linux", sizeof buf.sysname - 1);
  strncpy(buf.release, LINUX_RELEASE, sizeof buf.release - 1);
  strncpy(buf.version, LINUX_VERSION, sizeof buf.version - 1);
  strncpy(buf.machine, "x86_64", sizeof buf.machine - 1);
  strncpy(buf.domainname, "GNU/Linux", sizeof buf.domainname - 1);
  
#ifdef _WIN32
  strncpy(buf.nodename, "dummy_hostname", sizeof buf.nodename - 1);
#else
  int err = syswrap(gethostname(buf.nodename, sizeof buf.nodename - 1));
  if (err < 0) {
    return err;
  }
#endif

  if (copy_to_user(buf_ptr, &buf, sizeof(struct utsname))) {
    return -LINUX_EFAULT;
  }

  return 0;
}

DEFINE_SYSCALL(arch_prctl, int, code, gaddr_t, addr)
{
  uint64_t t;

  switch (code) {
  case LINUX_ARCH_SET_GS:
    write_register(VMM_X64_GS_BASE, addr);
    return 0;
  case LINUX_ARCH_SET_FS:
    write_register(VMM_X64_FS_BASE, addr);
    return 0;
  case LINUX_ARCH_GET_FS:
    read_register(VMM_X64_FS_BASE, &t);
    if (copy_to_user(addr, &t, sizeof t))
      return -LINUX_EFAULT;
    return 0;
  case LINUX_ARCH_GET_GS:
    read_register(VMM_X64_GS_BASE, &t);
    if (copy_to_user(addr, &t, sizeof t))
      return -LINUX_EFAULT;
    return 0;
  default:
    return -LINUX_EINVAL;
  }
}

