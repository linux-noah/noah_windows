#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <cpuid.h>
#include <getopt.h>
#include <string.h>
#include <sys/syslimits.h>
#include <libgen.h>
#include <strings.h>
#include <fcntl.h>

#include "common.h"
#include "vm.h"
#include "mm.h"
#include "noah.h"
#include "syscall.h"
#include "linux/errno.h"
#include "x86/irq_vectors.h"
#include "x86/specialreg.h"
#include "x86/vm.h"
#include "x86/vmx.h"
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <mach-o/dyld.h>

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

int
task_run()
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

  while (task_run() == 0) {

    /* dump_instr(); */
    /* print_regs(); */

    uint64_t exit_reason;
    get_vcpu_state(VMM_CTRL_EXIT_REASON, &exit_reason);

    switch (exit_reason) {
    case VMM_EXIT_VMCALL:
      printk("reason: vmcall\n");
      assert(false);
      break;

    case VMM_EXIT_EXCEPTION: {
      /* References:
       * - Intel SDM 27.2.2, Table 24-15: Information for VM Exits Due to Vectored Events
       */
      uint64_t exc_vec;
      get_vcpu_state(VMM_CTRL_EXCEPTION_VECTOR, &exc_vec);
      switch (exc_vec) {
      case X86_VEC_PF: {
        // TODO
        printk("page fault: caused by guest linear address\n");
        // send_signal(getpid(), LINUX_SIGSEGV);
      }
      case X86_VEC_UD: {
        uint64_t rip;
        read_register(VMM_X64_RIP, &rip);
        if (is_syscall(rip)) {
          int r = handle_syscall();
          read_register(VMM_X64_RIP, &rip); /* reload rip for execve */
          write_register(VMM_X64_RIP, rip + 2);
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
    default:
      printk("other exit reason: %llu\n", exit_reason);
    }
  }

  __builtin_unreachable();
}

void
init_special_regs()
{
  uint64_t cr0;
  read_register(VMM_X64_CR0, &cr0);
  write_register(VMM_X64_CR0, (cr0 & ~CR0_EM) | CR0_MP);

  uint64_t cr4;
  read_register(VMM_X64_CR4, &cr4);
  write_register(VMM_X64_CR4, cr4 | CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_VMXE | CR4_OSXSAVE);

  uint64_t efer;
  read_register(VMM_X64_EFER, &efer);
  write_register(VMM_X64_EFER, efer | EFER_LME | EFER_LMA);
}

struct gate_desc idt[256] __page_aligned;
gaddr_t idt_ptr;

void
init_idt()
{
  idt_ptr = kmap(idt, 0x1000, PROT_READ | PROT_WRITE);

  write_register(VMM_X64_IDT_BASE, idt_ptr);
  write_register(VMM_X64_IDT_LIMIT, sizeof idt);
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
  struct fxregs_state {
    uint16_t cwd; /* Control Word                    */
    uint16_t swd; /* Status Word                     */
    uint16_t twd; /* Tag Word                        */
    uint16_t fop; /* Last Instruction Opcode         */
    union {
      struct {
        uint64_t rip; /* Instruction Pointer             */
        uint64_t rdp; /* Data Pointer                    */
      };
      struct {
        uint32_t fip; /* FPU IP Offset                   */
        uint32_t fcs; /* FPU IP Selector                 */
        uint32_t foo; /* FPU Operand Offset              */
        uint32_t fos; /* FPU Operand Selector            */
      };
    };
    uint32_t mxcsr;       /* MXCSR Register State */
    uint32_t mxcsr_mask;  /* MXCSR Mask           */
    uint32_t st_space[32]; /* 8*16 bytes for each FP-reg = 128 bytes */
    uint32_t xmm_space[64]; /* 16*16 bytes for each XMM-reg = 256 bytes */
    uint32_t __padding[12];
    union {
      uint32_t __padding1[12];
      uint32_t sw_reserved[12];
    };
  } __attribute__((aligned(16))) fx;

  /* emulate 'fninit'
   * - http://www.felixcloutier.com/x86/FINIT:FNINIT.html
   */
  fx.cwd = 0x037f;
  fx.swd = 0;
  fx.twd = 0xffff;
  fx.fop = 0;
  fx.rip = 0;
  fx.rdp = 0;

  /* default configuration for the SIMD core */
  fx.mxcsr = 0x1f80;
  fx.mxcsr_mask = 0;

  write_fpstate(&fx, sizeof fx);
}

static void
init_first_proc(const char *root)
{
  proc = (struct proc) {
    .nr_tasks = 1,
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .mm = malloc(sizeof(struct mm)),
  };
  INIT_LIST_HEAD(&proc.tasks);
  list_add(&task.head, &proc.tasks);
  init_mm(proc.mm);
  // init_signal();
  int rootfd = open(root, O_RDONLY | O_DIRECTORY);
  if (rootfd < 0) {
    perror("could not open initial root directory");
    exit(1);
  }
  // init_fileinfo(rootfd);
  close(rootfd);
  proc.pfutex = kh_init(pfutex);
  pthread_mutex_init(&proc.futex_mutex, NULL);
  proc.cred = (struct cred) {
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .uid = getuid(),
    .euid = geteuid(),
    .suid = geteuid(),
  };

  task.tid = getpid();
}

static void
init_vkernel(const char *root)
{
  init_mm(&vkern_mm);
  init_shm_malloc();
  init_page();
  init_special_regs();
  init_segment();
  init_idt();
  init_regs();
  init_fpu();

  init_first_proc(root);
}

void
drop_privilege(void)
{
  if (seteuid(getuid()) != 0) {
    panic("drop_privilege");
  }
}

int sys_setresuid(int, int, int);
void
elevate_privilege(void)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  proc.cred.euid = 0;
  proc.cred.suid = 0;
  if (seteuid(0) != 0) {
    panic("elevate_privilege");
  }
  pthread_rwlock_unlock(&proc.cred.lock);
}

noreturn void
die_with_forcedsig(int sig)
{
  // TODO
  abort();
}

void
check_platform_version(void)
{
  int32_t b;
  size_t len = sizeof b;

  if (sysctlbyname("kern.hv_support", &b, &len, NULL, 0) < 0) {
    perror("sysctl kern.hv_support");
  }
  if (b == 0) {
    fprintf(stderr, "Your cpu seems too old. Buy a new mac!\n");
    exit(1);
  }
}

int
main(int argc, char *argv[], char **envp)
{
  drop_privilege();

  check_platform_version();

  char root[PATH_MAX] = {};

  int c;
  enum {PRINTK_PATH, WARNK_PATH, STRACE_PATH, MAX_DEBUG_PATH};
  char debug_paths[3][PATH_MAX] = {};
  struct option long_options[] = {
    { "output", required_argument, NULL, 'o'},
    { "strace", required_argument, NULL, 's'},
    { "warning", required_argument, NULL, 'w'},
    { "mnt", required_argument, NULL, 'm' },
    { 0, 0, 0, 0 }
  };

  while ((c = getopt_long(argc, argv, "+o:w:s:m:", long_options, NULL)) != -1) {
    switch (c) {
    case 'o':
      strncpy(debug_paths[PRINTK_PATH], optarg, PATH_MAX);
      break;
    case 'w':
      strncpy(debug_paths[WARNK_PATH], optarg, PATH_MAX);
      break;
    case 's':
      strncpy(debug_paths[STRACE_PATH], optarg, PATH_MAX);
      break;
    case 'm':
      if (realpath(optarg, root) == NULL) {
        perror("Invalid --mnt flag: ");
        exit(1);
      }
      argv[optind - 1] = root;
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc == 0) {
    abort();
  }

  create_vm();

  init_vkernel(root);

  for (int i = PRINTK_PATH; i < MAX_DEBUG_PATH; i++) {
    static void (* init_funcs[3])(const char *path) = {
      [PRINTK_PATH] = init_printk,
      [STRACE_PATH] = init_meta_strace,
      [WARNK_PATH]  = init_warnk
    };
    if (debug_paths[i][0] != '\0') {
      init_funcs[i](debug_paths[i]);
    }
  }

  int err;
  if ((err = do_exec(argv[0], argc, argv, envp)) < 0) {
    errno = linux_to_darwin_errno(-err);
    perror("Error");
    exit(1);
  }

  main_loop(0);

  destroy_vm();

  return 0;
}
