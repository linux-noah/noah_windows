#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <string>
#include <Windows.h>
#include <boost/format.hpp>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "vm.h"
#include "syscall.h"

void
clone_proc(struct proc *dst_proc, struct proc *src_proc)
{
  *dst_proc = *src_proc;
  dst_proc->pid = vkern->next_pid++;
  dst_proc->mm = vkern_shm->construct<struct mm>(bip::anonymous_instance)();
  clone_mm(dst_proc->mm.get(), src_proc->mm.get());
  dst_proc->vcpu_state = vkern_shm->construct<struct vcpu_state>(bip::anonymous_instance)();
  // TODO: Copy the all left. Leave it later assuming currently 
  //       we are not using these structures
}

int
platform_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  struct proc *new_proc = vkern_shm->construct<struct proc>(bip::anonymous_instance)();
  clone_proc(new_proc, proc);
  get_vcpu_state(new_proc->vcpu_state.get());
  TCHAR bin[MAX_PATH];
  auto bin_len = GetModuleFileName(NULL, bin, MAX_PATH);
  if (bin_len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
    return -LINUX_ENAMETOOLONG;
  }
  auto cur_cmd = GetCommandLine();
  auto new_cmd = str(boost::format("%1 --child=%2 --shm_fd=%3") % cur_cmd % new_proc->pid % reinterpret_cast<uint64_t>(vkern_shm));
  TCHAR *new_cmd_cstr = reinterpret_cast<TCHAR *>(alloca(new_cmd.size()));
  strcpy(new_cmd_cstr, new_cmd.c_str());
  STARTUPINFO info;
  PROCESS_INFORMATION proc_info;
  auto succ = CreateProcess(bin, new_cmd_cstr, NULL, NULL, true, NULL, NULL, NULL, &info, &proc_info);
  if (!succ) {
    return -LINUX_EINVAL; // TODO
  }
  write_register(VMM_X64_RAX, new_proc->pid);

  return 0;
}

int
platform_restore_proc(unsigned pid)
{
  proc = (*vkern->procs)[pid].get();
  restore_mm(proc->mm.get());
  proc->vcpu_state->regs[VMM_X64_RAX].val = 0;
  set_vcpu_state(proc->vcpu_state.get());
  return 0;
}
