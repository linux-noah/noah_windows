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

int
platform_restore_proc(uint64_t proc_offset)
{
  proc = reinterpret_cast<struct proc *>(reinterpret_cast<uint64_t>(vkern_shm->get_address()) + proc_offset);
  proc->pid = getpid();
  vkern->procs->emplace(proc->pid, offset_ptr<struct proc>(proc));
  restore_mm(proc->mm.get());
  set_vcpu_state(proc->vcpu_state.get());
  return 0;
}

void
clone_proc(struct proc *dst_proc, struct proc *src_proc)
{
  *dst_proc = *src_proc;
  dst_proc->pid = -1;
  dst_proc->mm = vkern_shm->construct<struct proc_mm>(bip::anonymous_instance)();
  clone_mm(dst_proc->mm.get(), src_proc->mm.get());
  dst_proc->vcpu_state = vkern_shm->construct<struct vcpu_state>(bip::anonymous_instance)();
  // TODO: Copy the all left. Leave it later assuming currently 
  //       we are not using these structures
}

void
restore_vkernel(platform_handle_t shm_fd);

int
platform_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  struct proc *new_proc = vkern_shm->construct<struct proc>(bip::anonymous_instance)();
  clone_proc(new_proc, proc);
  get_vcpu_state(new_proc->vcpu_state.get());
  new_proc->vcpu_state->regs[VMM_X64_RAX].val = 0;
  get_vcpu_state(proc->vcpu_state.get());
  TCHAR bin[MAX_PATH];
  auto bin_len = GetModuleFileName(NULL, bin, MAX_PATH);
  if (bin_len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
    return -LINUX_ENAMETOOLONG;
  }
  // TODO: neater one
  auto cur_cmd = GetCommandLine();
  auto new_cmd = str(
    boost::format("%1% --child=%2% --shm_fd=%3% %4%")
    % noah_argv[0]
    % (reinterpret_cast<uint64_t>(new_proc) - reinterpret_cast<uint64_t>(vkern_shm->get_address()))
    % reinterpret_cast<uint64_t>(vkern->shm_handle)
    % noah_opts["linux_bin"].as<std::string>()
  );
  TCHAR *new_cmd_cstr = reinterpret_cast<TCHAR *>(alloca(new_cmd.size() + 1));
  strcpy(new_cmd_cstr, new_cmd.c_str());
  SECURITY_ATTRIBUTES sec;
  sec.nLength = sizeof(SECURITY_ATTRIBUTES);
  sec.lpSecurityDescriptor = NULL;
  sec.bInheritHandle = true;
  STARTUPINFO strtup_info;
  memset(&strtup_info, 0, sizeof(strtup_info));
  strtup_info.cb = sizeof(strtup_info);
  PROCESS_INFORMATION proc_info;
  auto succ = CreateProcess(bin, new_cmd_cstr, &sec, &sec, true, 0, NULL, NULL, &strtup_info, &proc_info);
  if (!succ) {
    return -LINUX_EINVAL; // TODO
  }
  new_proc->platform.handle = proc_info.hProcess;

  return proc_info.dwProcessId;
}
