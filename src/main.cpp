#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <boost/program_options.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>
#include <processor_flags.h>
#include <processor_msrs.h>
#include <intrin.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <sys/sysctl.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#include "cross_platform.h"
#include "common.h"
#include "noah.h"
#include "vm.h"
#include "mm.h"
#include "syscall.h"
#include "proc.h"
#include "linux/errno.h"
#include "x86/irq_vectors.h"
#include "x86/vm.h"
#include "x86/vmx.h"

struct eval_tsc *shared_tsc;

static bool
is_syscall(uint64_t rip)
{
  static const ushort OP_SYSCALL = 0x050f;
  ushort op;

  if (copy_from_user(&op, rip, sizeof op))
    return false;
  return op == OP_SYSCALL;
}

static int
handle_syscall(void)
{
  uint64_t rax;
  read_register(VMM_X64_RAX, &rax);
  if (rax >= NR_SYSCALLS) {
    warnk("unknown system call: %lld\n", rax);
    // send_signal(getpid(), LINUX_SIGSYS);
  }
  uint64_t rdi, rsi, rdx, r10, r8, r9;
  read_register(VMM_X64_RDI, &rdi);
  read_register(VMM_X64_RSI, &rsi);
  read_register(VMM_X64_RDX, &rdx);
  read_register(VMM_X64_R10, &r10);
  read_register(VMM_X64_R8, &r8);
  read_register(VMM_X64_R9, &r9);
  uint64_t retval = sc_handler_table[rax](rdi, rsi, rdx, r10, r8, r9);
  write_register(VMM_X64_RAX, retval);

  // TODO: Handle sigreturn
  return 0;
}

void
handle_pagefault(gaddr_t addr)
{
  // TODO
  printk("page fault: caused by guest linear address 0x%" PRIx64 "\n", addr);
  abort();
  // send_signal(getpid(), LINUX_SIGSEGV);
}

int
task_run(void)
{
  /* handle pending signals */
  // if (has_sigpending()) {
  //   handle_signal();
  // }
  return run_vcpu();
}

void
main_loop(int return_on_sigret)
{
  /* main_loop returns only if return_on_sigret == 1 && rt_sigreturn is invoked.
     see also: rt_sigsuspend */

  /*
   * System call and exception hooking mecahism depends on whether the platform's
   * VMM allows VMExit on exceptions.
   * If it allows, exceptions are delivered directly by VMM and system calls are 
   * hooked by clearing EFER_SCE and inspecting #UD.
   * Otherwise, currently they are hooked by putting trampoline codes in the kernel space.
   * Those trampoline codes execute "hlt" instruction to cause VMExit.
   */
  while (1) {
    vcpu_sync_registers_with_cache();
    shared_tsc->pre_taskrun = __rdtsc();
    int ret = task_run();
    shared_tsc->post_taskrun = __rdtsc();
    if (ret != 0)
      break;


    /* dump_instr(); */
    /* print_regs(); */

    uint64_t exit_reason;
    get_vcpu_control_state(VMM_CTRL_EXIT_REASON, &exit_reason);

    switch (exit_reason) {
    // The trampoline issues HLT for system call and exception in HAXM
    case VMM_EXIT_HLT: {
      uint64_t rip;
      read_register(VMM_X64_RIP, &rip);
      if (rip - 1 == vkern->mm->syscall_entry_addr) {
        uint64_t rcx;
        read_register(VMM_X64_RCX, &rcx);
        write_register(VMM_X64_RIP, rcx); // Set RIP to the next instruction of syscall
        int r = handle_syscall();
        if (return_on_sigret && r < 0) {
          return;
        }
        continue;
      }

      assert(false);
      break;
    }

    case VMM_EXIT_MMIO: {
      scoped_lock lock(proc->mm->mutex);
      auto addr = vcpu_mmio_tunnel->gpa;
      auto region = find_region(addr, proc->mm.get());
      if (region == nullptr) {
        handle_pagefault(addr);
        break;
      }
      // Check should_cow since adding PROT_WRITE by mprotect just after page_fault 
      // could also cause this situation
      if (!(region->prot & LINUX_PROT_WRITE) || !region->should_cow) {
        handle_pagefault(addr);
        break;
      }

      // Copy On Write
      if (vcpu_mmio_tunnel->direction == VMM_MMIO_COPY) {
        panic("Unimplemented. CoW by MOVS \n");
      }
      handle_cow(proc->mm.get(), region, addr, vcpu_mmio_tunnel->size, *vcpu_mmio_tunnel->value);
      break;
    }

    case VMM_EXIT_VMCALL:
      printk("reason: vmcall\n");
      assert(false);
      break;

    case VMM_EXIT_EXCEPTION: {
      /* References:
       * - Intel SDM 27.2.2, Table 24-15: Information for VM Exits Due to Vectored Events
       */
#ifdef _WIN32
      // Temorary code for debug
      uint64_t native_exit_reason = 0;
      get_vcpu_control_state(VMM_CTRL_NATIVE_EXIT_REASON, &native_exit_reason);
      //abort();
      break;
#endif
      uint64_t exc_vec;
      get_vcpu_control_state(VMM_CTRL_EXCEPTION_VECTOR, &exc_vec);
      switch (exc_vec) {
      case X86_VEC_PF: {
        handle_pagefault(0 /*TODO*/);
      }
      case X86_VEC_UD: {
        uint64_t rip;
        read_register(VMM_X64_RIP, &rip);
        if (is_syscall(rip)) {
          write_register(VMM_X64_RIP, rip + 2); // Increment RIP to the next instruction
          int r = handle_syscall();
          if (return_on_sigret && r < 0) {
            return;
          }
          continue;
        }
        /* FIXME */
        warnk("invalid opcode! (rip = %p): ", (void *) rip);
        dump_instr();
        // send_signal(getpid(), LINUX_SIGILL);
      }
      case X86_VEC_DE:
      case X86_VEC_DB:
      case X86_VEC_BP:
      case X86_VEC_OF:
      case X86_VEC_BR:
      case X86_VEC_NM:
      case X86_VEC_DF:
      case X86_VEC_TS:
      case X86_VEC_NP:
      case X86_VEC_SS:
      case X86_VEC_GP:
      case X86_VEC_MF:
      case X86_VEC_AC:
      case X86_VEC_MC:
      case X86_VEC_XM:
      case X86_VEC_VE:
      case X86_VEC_SX:
      default:
        /* FIXME */
        warnk("Unimplemented exception thrown: %" PRIx64 "\n", exc_vec);
        dump_instr();
        exit(1);                /* TODO */
      }
      break;
    }
    case VMM_EXIT_SHUTDOWN: {
      uint64_t native_exit_reason = 0;
      get_vcpu_control_state(VMM_CTRL_NATIVE_EXIT_REASON, &native_exit_reason);
      uint64_t rip;
      read_register(VMM_X64_RIP, &rip);
      // TODO: Define Basic exit reason constants in libhv
      printk("Unexpected VMM_EXIT_SHUTDOWN\n");
      abort();
      break;
    }

    default:
      printk("other exit reason: %llu\n", exit_reason);
#ifdef _WIN32
      // TODO: Implement VMM_CTRL_NATIVE_EXIT_REASON in libhv
      uint64_t native_exit_reason = 0;
      get_vcpu_control_state(VMM_CTRL_NATIVE_EXIT_REASON, &native_exit_reason);
      printk("native exit reason: %llu\n", native_exit_reason);
      uint64_t rip;
      read_register(VMM_X64_RIP, &rip);
      abort();
#endif
    }
  }

  UNREACHABLE();
}

// MSRs set by this function will be restored in restore_vkernel
void
vkern_set_msr(uint32_t reg, uint64_t value)
{
  (*vkern->msrs)[reg] = value;
  write_msr(reg, value);
}

void
init_special_regs()
{
  uint64_t cr0;
  read_register(VMM_X64_CR0, &cr0);
  write_register(VMM_X64_CR0, (cr0 & ~X86_CR0_EM) | X86_CR0_MP);

  uint64_t cr4;
  read_register(VMM_X64_CR4, &cr4);
  write_register(VMM_X64_CR4, cr4 | X86_CR4_PAE | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT | X86_CR4_VMXE | X86_CR4_OSXSAVE);

  uint64_t efer;
  read_register(VMM_X64_EFER, &efer);
  efer |= EFER_LME | EFER_LMA | EFER_NX;
  write_register(VMM_X64_EFER, efer);
  vkern_set_msr(MSR_IA32_EFER, efer);
}

TYPEDEF_PAGE_ALIGNED(struct gate_desc) gate_desc_t[256];
TYPEDEF_PAGE_ALIGNED(uint8_t) syscall_entry_t[1];
TYPEDEF_PAGE_ALIGNED(uint8_t) exception_entry_t[256];

void
init_idt()
{
  syscall_entry_t *syscall_entry;
  exception_entry_t *exception_entry;
  gate_desc_t *idt;

  vkern->mm->idt_addr = kalloc_aligned(&idt, PROT_READ | PROT_WRITE, 
    roundup(sizeof(*idt), PAGE_SIZE(PAGE_4KB)), PAGE_SIZE(PAGE_4KB));

  write_register(VMM_X64_IDT_BASE, vkern->mm->idt_addr);
  write_register(VMM_X64_IDT_LIMIT, sizeof idt);

#ifdef _WIN32
  // Set up syscall and interrupt trampolines
  static const uint8_t OP_HLT = '\xf4';
  uint64_t efer;
  read_msr(MSR_IA32_EFER, &efer);
  efer |= EFER_SCE;
  vkern_set_msr(MSR_IA32_EFER, efer);

  vkern->mm->syscall_entry_addr = kalloc_aligned(&syscall_entry, PROT_READ | PROT_WRITE, PAGE_SIZE(PAGE_4KB), PAGE_SIZE(PAGE_4KB));
  (*syscall_entry)[0] = OP_HLT;
  vkern_set_msr(MSR_IA32_LSTAR, vkern->mm->syscall_entry_addr);
  vkern_set_msr(MSR_IA32_FMASK, 0);
  vkern_set_msr(MSR_IA32_FMASK, 0);
  vkern_set_msr(MSR_IA32_STAR, GSEL(SEG_CODE, 0) << 32);

  vkern->mm->exception_entry_addr = kalloc_aligned(&exception_entry, PROT_READ | PROT_WRITE, PAGE_SIZE(PAGE_4KB), PAGE_SIZE(PAGE_4KB));
  for (int i = 0; i < 256; i++) {
    (*exception_entry)[i] = OP_HLT;
    // Set idt[i] to there
  }
#endif


}

void
init_regs()
{
  /* set up cpu regs */
  write_register(VMM_X64_RFLAGS, 0x2);
}

void
init_fpu()
{
  // TODO
}

static void
init_first_proc(const char *root)
{
  proc = vkern_shm->construct<struct proc>(bip::anonymous_instance)();
  memset(proc, 0, sizeof(proc));
  proc->pid = vkern->next_pid++;
  proc->nr_tasks = 1;
  pthread_rwlock_init(&proc->lock, NULL);
  proc->mm = vkern_shm->construct<struct proc_mm>(bip::anonymous_instance)();
  INIT_LIST_HEAD(&proc->tasks);
  list_add(&task.head, &proc->tasks);
  proc->vcpu_state = vkern_shm->construct<struct vcpu_state>(bip::anonymous_instance)();
  // init_signal();
  /*
  int rootfd = open(root, O_RDONLY | O_DIRECTORY);
  if (rootfd < 0) {
    perror("could not open initial root directory");
    exit(1);
  }
  // init_fileinfo(rootfd);
  close(rootfd);
  */
  proc->pfutex = kh_init(pfutex);
  //pthread_mutex_init(&proc->futex_mutex, NULL);
  /*
  proc = {
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .uid = getuid(),
    .euid = geteuid(),
    .suid = geteuid(),
  };
  */

  task.tid = proc->pid;
  vkern->procs->emplace(proc->pid, offset_ptr<struct proc>(proc));
#ifdef _WIN32
  proc->platform.handle = GetCurrentProcess(); // The handle of the first proc is not used by anyone now. So, pseudo handle suffices
#endif
}

struct vkern *vkern;
bip::managed_external_buffer *vkern_shm;

platform_handle_t
init_vkern_shm()
{
  platform_handle_t shm_handle;
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT;
#else
  const int platform_mflags = MAP_SHARED | MAP_ANONYMOUS;
#endif
  void *buf;
  int err = platform_map_mem(&buf, &shm_handle, vkern_shm_size + PAGE_SIZE(PAGE_4KB), PROT_READ | PROT_WRITE | PROT_EXEC, platform_mflags);
  if (err < 0) {
    abort();
  }
  *reinterpret_cast<unsigned *>(buf) = 0xdeadbeef; // A guard to check the memory is successfully shared
  vkern_shm = new bip::managed_external_buffer(bip::create_only, (char *)buf + PAGE_SIZE(PAGE_4KB), vkern_shm_size);
  return shm_handle;
}


void
init_vkern_struct()
{
  platform_handle_t shm_handle = init_vkern_shm();
  vkern = vkern_shm->construct<struct vkern>("vkern", std::nothrow)();
  vkern->shm_handle = shm_handle;
  vkern->shm_allocator = vkern_shm->construct<extbuf_allocator_t<void>>
                                      (bip::anonymous_instance)(vkern_shm->get_segment_manager());
  vkern->msrs = vkern_shm->construct<vkern::msrs_t>(bip::anonymous_instance)(*vkern->shm_allocator);
  vkern->mm = vkern_shm->construct<vkern_mm>(bip::anonymous_instance)();
  vkern->next_pid = 2;
  vkern->procs = vkern_shm->construct<vkern::procs_t>
                              (bip::anonymous_instance)(*vkern->shm_allocator);
}

static void
init_vkernel(const char *root)
{
  init_vkern_struct();
  init_page();
  init_special_regs();
  init_segment();
  init_idt();
  init_regs();
  init_fpu();

  init_first_proc(root);
}

void
restore_vkernel(platform_handle_t shm_fd)
{
#ifdef _WIN32
  void *buf;
  platform_restore_mapped_mem(&buf, shm_fd, vkern_shm_size + PAGE_SIZE(PAGE_4KB), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_INHERIT);
  assert(*reinterpret_cast<int *>(buf) == 0xdeadbeef); // Check the guard's value
  vkern_shm = new bip::managed_external_buffer(bip::open_only, (char *)buf + PAGE_SIZE(PAGE_4KB), vkern_shm_size);
  vkern = vkern_shm->find<struct vkern>("vkern").first;
#endif
  restore_mm(vkern->mm.get());
  for (auto entry : *vkern->msrs) {
    write_msr(entry.first, entry.second);
  }
}

void
drop_privilege(void)
{
#if defined(__unix__) || defined(__APPLE__)
  if (seteuid(getuid()) != 0) {
    panic("drop_privilege");
  }
#endif
}

#if defined(__unix__) || defined(__APPLE__)
int sys_setresuid(int, int, int);
#endif
void
elevate_privilege(void)
{
#if defined(__unix__) || defined(__APPLE__)
  pthread_rwlock_wrlock(&proc->cred.lock);
  proc->cred.euid = 0;
  proc->cred.suid = 0;
  if (seteuid(0) != 0) {
    panic("elevate_privilege");
  }
  pthread_rwlock_unlock(&proc->cred.lock);
#endif
}

[[ noreturn ]] void
die_with_forcedsig(int sig)
{
  // TODO
  abort();
}

void
check_platform_version(void)
{
#ifdef __APPLE__
  int32_t b;
  size_t len = sizeof b;

  if (sysctlbyname("kern.hv_support", &b, &len, NULL, 0) < 0) {
    perror("sysctl kern.hv_support");
  }
  if (b == 0) {
    fprintf(stderr, "Your cpu seems too old. Buy a new mac!\n");
    exit(1);
  }
#endif
}

namespace po = boost::program_options;
po::variables_map noah_opts;
int noah_argc;
char **noah_argv;

int
main(int argc, char *argv[], char **envp)
{
  drop_privilege();

  check_platform_version();

  po::options_description desc("Available options");
  desc.add_options()
    ("help,h", "show this message")
    ("output,o", po::value<std::string>(), "path to log file")
    ("strace,s", po::value<std::string>(), "path meta strace file")
    ("warning,w", po::value<std::string>(), "path to warning log file")
    ("mnt,m", po::value<std::string>()->default_value("~/.noah/tree"), "path to root directory")
    ("child,c", po::value<unsigned>(), "mark this process as a forked process and pass its pid")
    ("shm_fd,f", po::value<uint64_t>(), "inherited shared memory handle")
    ("linux_bin,b", po::value<std::string>(), "path to the Linux ELF to execute");
  po::positional_options_description pos;
  pos.add("linux_bin", -1);

  po::store(po::command_line_parser(argc, argv)
              .options(desc)
              .positional(pos)
              .run(),
            noah_opts);
  po::notify(noah_opts);
  noah_argc = argc;
  noah_argv = argv;

  if (noah_opts.count("help") || !noah_opts.count("linux_bin")) {
    std::cout << "Usage: ./noah linux_bin" << std::endl;
    std::cout << desc << std::endl;
    return 1;
  }

  create_vm();
  
  // TODO: realpath
  if (!noah_opts.count("child")) {
    init_vkernel(noah_opts["mnt"].as<std::string>().c_str());

    if (noah_opts.count("output")) {
      init_printk(noah_opts["output"].as<std::string>().c_str());
    }
    if (noah_opts.count("strace")) {
      init_meta_strace(noah_opts["strace"].as<std::string>().c_str());
    }
    if (noah_opts.count("warning")) {
      init_warnk(noah_opts["warning"].as<std::string>().c_str());
    }

    int err;
    if ((err = do_exec(noah_opts["linux_bin"].as<std::string>().c_str(), argc, argv, envp)) < 0) {
      errno = linux_to_native_errno(-err);
      perror("Error");
      exit(1);
    }
    do_mmap(0x1000, 0x1000, PROT_READ | PROT_WRITE, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);
    shared_tsc = (struct eval_tsc *)guest_to_host(0x1000);

  } else {
    restore_vkernel(reinterpret_cast<platform_handle_t>(noah_opts["shm_fd"].as<uint64_t>()));
    platform_restore_proc(noah_opts["child"].as<unsigned>());
    shared_tsc = (struct eval_tsc *)guest_to_host(0x1000);
  }

  main_loop(0);

  destroy_vm();

  return 0;
}

