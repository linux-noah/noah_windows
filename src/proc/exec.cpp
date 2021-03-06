#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cctype>

#include <fcntl.h>
#include <sys/stat.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <sys/resource.h>
#endif
#elif defined(_WIN32)
#include <malloc.h>
#define alloca _alloca
#endif

#include "common.h"
#include "noah.h"
#include "vm.h"
#include "mm.h"
#include "x86/vm.h"
#include "elf.h"

#include "linux/common.h"
#include "linux/mman.h"
#include "linux/misc.h"
#include "linux/time.h"
#include "linux/fs.h"

void init_userstack(int argc, char *argv[], char **envp, uint64_t exe_base, const Elf64_Ehdr *ehdr, uint64_t global_offset, uint64_t interp_base);

int
load_elf_interp(const char *path, uint64_t load_addr)
{
  char *data;
  platform_handle_t data_handle;
  Elf64_Ehdr *h;
  uint64_t map_top = 0;
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT | MAP_FILE_PRIVATE;
#else
  const int platform_mflags = MAP_PRIVATE;
#endif

  int size = platform_alloc_filemapping((void **)&data, &data_handle, -1, PROT_READ | PROT_EXEC, platform_mflags, 0, path);
  if (size < 0) {
    fprintf(stderr, "load_elf_interp, could not open file: %s\n", path);
    abort();
  }

  h = (Elf64_Ehdr *)data;

  assert(IS_ELF(*h));

  if (! (h->e_type == ET_EXEC || h->e_type == ET_DYN)) {
    return -LINUX_ENOEXEC;
  }
  if (h->e_machine != EM_X86_64) {
    return -LINUX_ENOEXEC;
  }

  Elf64_Phdr *p = (Elf64_Phdr *)(data + h->e_phoff);

  for (int i = 0; i < h->e_phnum; i++) {
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    uint64_t p_vaddr = p[i].p_vaddr + load_addr;

    uint64_t mask = PAGE_SIZE(PAGE_4KB) - 1;
    uint64_t vaddr = p_vaddr & ~mask;
    uint64_t offset = p_vaddr & mask;
    uint64_t size = roundup(p[i].p_memsz + offset, PAGE_SIZE(PAGE_4KB));

    int prot = 0;
    if (p[i].p_flags & PF_X) prot |= LINUX_PROT_EXEC;
    if (p[i].p_flags & PF_W) prot |= LINUX_PROT_WRITE;
    if (p[i].p_flags & PF_R) prot |= LINUX_PROT_READ;

    assert(vaddr != 0);
    do_mmap(vaddr, size, PROT_READ | PROT_WRITE, prot, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

    copy_to_user(vaddr + offset, data + p[i].p_offset, p[i].p_filesz);

    map_top = MAX(map_top, roundup(vaddr + size, PAGE_SIZE(PAGE_4KB)));
  }

  write_register(VMM_X64_RIP, load_addr + h->e_entry);
  proc->mm->start_brk = map_top;

  platform_free_filemapping(data, data_handle, size);

  return 0;
}

int
load_elf(Elf64_Ehdr *ehdr, int argc, char *argv[], char **envp)
{
  uint64_t map_top = 0;

  assert(IS_ELF(*ehdr));

  if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
    fprintf(stderr, "not an executable file");
    fflush(stderr);
    return -LINUX_ENOEXEC;
  }
  if (ehdr->e_machine != EM_X86_64) {
    fprintf(stderr, "not an x64 executable");
    fflush(stderr);
    return -LINUX_ENOEXEC;
  }

  Elf64_Phdr *p = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);

  uint64_t load_base = 0;
  bool load_base_set = false;

  uint64_t global_offset = 0;
  if (ehdr->e_type == ET_DYN) {
    /* NB: Program headers in elf files of ET_DYN can have 0 as their own p_vaddr. */
    global_offset = 0x400000;   /* default base address */
  }

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    uint64_t p_vaddr = p[i].p_vaddr + global_offset;

    uint64_t mask = PAGE_SIZE(PAGE_4KB) - 1;
    uint64_t vaddr = p_vaddr & ~mask;
    uint64_t offset = p_vaddr & mask;
    uint64_t size = roundup(p[i].p_memsz + offset, PAGE_SIZE(PAGE_4KB));

    int prot = 0;
    if (p[i].p_flags & PF_X) prot |= LINUX_PROT_EXEC;
    if (p[i].p_flags & PF_W) prot |= LINUX_PROT_WRITE;
    if (p[i].p_flags & PF_R) prot |= LINUX_PROT_READ;

    assert(vaddr != 0);
    do_mmap(vaddr, size, PROT_READ | PROT_WRITE, prot, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

    copy_to_user(vaddr + offset, (char *)ehdr + p[i].p_offset, p[i].p_filesz);

    if (! load_base_set) {
      load_base = p[i].p_vaddr - p[i].p_offset + global_offset;
      load_base_set = true;
    }
    map_top = MAX(map_top, roundup(vaddr + size, PAGE_SIZE(PAGE_4KB)));
  }

  assert(load_base_set);

  int i;
  bool interp = false;
  for (i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type == PT_INTERP) {
      interp = true;
      break;
    }
  }
  if (interp) {
    char *interp_path = (char *)alloca(p[i].p_filesz + 1);
    memcpy(interp_path, (char *)ehdr + p[i].p_offset, p[i].p_filesz);
    interp_path[p[i].p_filesz] = 0;

    if (load_elf_interp(interp_path, map_top) < 0) {
      return -1;
    }
  }
  else {
    write_register(VMM_X64_RIP, ehdr->e_entry + global_offset);
    proc->mm->start_brk = map_top;
  }

  init_userstack(argc, argv, envp, load_base, ehdr, global_offset, interp ? map_top : 0);

  return 1;
}

#define SB_ARGC_MAX 2

int
load_script(const char *script, size_t len, const char *elf_path, int argc, char *argv[], char **envp)
{
  const char *script_end = script + len;
  char sb_argv[SB_ARGC_MAX][LINUX_PATH_MAX];
  int sb_argc;
  size_t n;

  script += 2;                  /* skip shebang */

  for (sb_argc = 0; sb_argc < SB_ARGC_MAX; ++sb_argc) {
    while (isspace(*script) && *script != '\n') {
      if (script == script_end)
        goto parse_end;
      script++;
    }

    for (n = 0; ! isspace(script[n]); ++n) {
      if (script + n == script_end)
        goto parse_end;
    }
    if (n == 0) {
      goto parse_end;
    }
    if (n > LINUX_PATH_MAX - 1) {
      return -LINUX_ENAMETOOLONG;
    }
    strncpy(sb_argv[sb_argc], script, n);
    sb_argv[sb_argc][n] = 0;

    script += n;                /* skip interp */
  }

 parse_end:
  if (sb_argc == 0) {
    return -LINUX_EFAULT;
  }

  int newargc = sb_argc + argc;
  char **newargv = (char **)alloca(newargc);
  for (int i = 0; i < sb_argc; ++i) {
    newargv[i] = sb_argv[i];
  }
  newargv[sb_argc] = (char *)elf_path;
  memcpy(newargv + sb_argc + 1, argv + 1, (argc - 1) * sizeof(char *));

  do_exec(newargv[0], newargc, newargv, envp);

  return 0;
}

uint64_t
push(const void *data, size_t n)
{
  uint64_t size = roundup(n, 8);
  uint64_t rsp;

  assert(data != 0);

  read_register(VMM_X64_RSP, &rsp);
  rsp -= size;
  write_register(VMM_X64_RSP, rsp);

  copy_to_user(rsp, data, n);

  return rsp;
}

void
init_userstack(int argc, char *argv[], char **envp, uint64_t exe_base, const Elf64_Ehdr *ehdr, uint64_t global_offset, uint64_t interp_base)
{
  static const uint64_t zero = 0;

  do_mmap(STACK_TOP - STACK_SIZE, STACK_SIZE, PROT_READ | PROT_WRITE, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

  write_register(VMM_X64_RSP, STACK_TOP);
  write_register(VMM_X64_RBP, STACK_TOP);

  char random[16];

  uint64_t rand_ptr = push(random, sizeof random);

  char **renvp;
  for (renvp = envp; *renvp; ++renvp)
    ;

  uint64_t total = 0, args_total = 0;

  for (int i = 0; i < argc; ++i) {
    total += strlen(argv[i]) + 1;
  }
  args_total = total;
  for (char **e = envp; *e; ++e) {
    total += strlen(*e) + 1;
  }

  char *buf = (char *)alloca(total);

  uint64_t off = 0;

  for (int i = 0; i < argc; ++i) {
    size_t len = strlen(argv[i]);
    memcpy(buf + off, argv[i], len + 1);
    off += len + 1;
  }
  for (char **e = envp; *e; ++e) {
    size_t len = strlen(*e);
    memcpy(buf + off, *e, len + 1);
    off += len + 1;
  }

  uint64_t args_start = push(buf, total);
  uint64_t args_end = args_start + args_total, env_end = args_start + total;

  Elf64_Auxv aux[] = {
    { AT_BASE, interp_base },
    { AT_ENTRY, ehdr->e_entry + global_offset },
    { AT_PHDR, exe_base + ehdr->e_phoff },
    { AT_PHENT, ehdr->e_phentsize },
    { AT_PHNUM, ehdr->e_phnum },
    { AT_PAGESZ, PAGE_SIZE(PAGE_4KB) },
    { AT_RANDOM, rand_ptr },
    { AT_NULL, 0 },
  };

  push(aux, sizeof aux);

  push(&zero, sizeof zero);

  uint64_t ptr = env_end;
  for (char **e = renvp - 1; e >= envp; --e) {
    ptr -= strlen(*e) + 1;
    push(&ptr, sizeof ptr);
    assert(strcmp(buf + (ptr - args_start), *e) == 0);
  }

  push(&zero, sizeof zero);

  ptr = args_end;
  for (int i = argc - 1; i >= 0; --i) {
    ptr -= strlen(argv[i]) + 1;
    push(&ptr, sizeof ptr);
    assert(strcmp(buf + (ptr - args_start), argv[i]) == 0);
  }

  uint64_t argc64 = argc;
  push(&argc64, sizeof argc64);
}

static void
init_reg_state(void)
{
  write_register(VMM_X64_RAX, 0);
  write_register(VMM_X64_RBX, 0);
  write_register(VMM_X64_RCX, 0);
  write_register(VMM_X64_RDX, 0);
  write_register(VMM_X64_RSI, 0);
  write_register(VMM_X64_RDI, 0);
  write_register(VMM_X64_R8, 0);
  write_register(VMM_X64_R9, 0);
  write_register(VMM_X64_R10, 0);
  write_register(VMM_X64_R11, 0);
  write_register(VMM_X64_R12, 0);
  write_register(VMM_X64_R13, 0);
  write_register(VMM_X64_R14, 0);
  write_register(VMM_X64_R15, 0);

  write_register(VMM_X64_FS, 0);
  write_register(VMM_X64_ES, 0);
  write_register(VMM_X64_GS, 0);
  write_register(VMM_X64_DS, 0);
  write_register(VMM_X64_CS, GSEL(SEG_CODE, 0));
  write_register(VMM_X64_DS, GSEL(SEG_DATA, 0));

  write_register(VMM_X64_FS_BASE, 0);
  write_register(VMM_X64_GS_BASE, 0);

  write_register(VMM_X64_LDTR, 0);

  init_fpu();
}

static void
prepare_newproc(void)
{
  /* Reinitialize proc and task structures */
  /* Not handling locks seriously now because multi-thread execve is not implemented yet */
  proc->nr_tasks = 1;
  vkern_shm->destroy_ptr(proc->mm.get());
  proc->mm = vkern_shm->construct<struct proc_mm>(bip::anonymous_instance)();
  init_reg_state();
  // reset_signal_state();
  // TODO: destroy LDT if it is implemented

  /* task.tid = getpid(); */
  task.clear_child_tid = task.set_child_tid = 0;
  task.robust_list = 0;
  // close_cloexec();
}

int
do_exec(const char *elf_path, int argc, char *argv[], char **envp)
{
  int err;
  char *data;
  platform_handle_t data_handle;
#ifdef _WIN32
  const int platform_mflags = MAP_INHERIT | MAP_FILE_PRIVATE;
#else
  const int platform_mflags = MAP_PRIVATE;
#endif
  
  // if ((err = do_access(elf_path, X_OK)) < 0) {
  //   return err;
  // }
  // if ((fd = vkern_open(elf_path, LINUX_O_RDONLY, 0)) < 0) {
  //  return fd;
  // }
  if (proc->nr_tasks > 1) {
    warnk("Multi-thread execve is not implemented yet\n");
    return -LINUX_EINVAL;
  }

  /*
  // File Read
  struct stat st;
  int fd = open(elf_path, O_RDONLY);
  fstat(fd, &st);
  int size = st.st_size;
  platform_map_mem(&data, size, PROT_READ | PROT_EXEC | PROT_WRITE);
  read(fd, data, size);
  */
  // Memory-mapped file
  int size = platform_alloc_filemapping((void **)&data, &data_handle, -1, PROT_READ | PROT_EXEC, platform_mflags, 0, elf_path);
  if (size < 0) {
    return size;
  }
  //close(fd);

  prepare_newproc();

  drop_privilege();

  if (4 <= size && memcmp(data, ELFMAG, 4) == 0) {
    if ((err = load_elf((Elf64_Ehdr *) data, argc, argv, envp)) < 0)
      return err;
    /*if (st.st_mode & 04000) {
      elevate_privilege();
    }*/
  }
  else if (2 <= size && data[0] == '#' && data[1] == '!') {
    if ((err = load_script(data, size, elf_path, argc, argv, envp)) < 0)
      return err;
  }
  /*else if (4 <= st.st_size && memcmp(data, "\xcf\xfa\xed\xfe", 4) == 0) {
    // Mach-O
    return syswrap(execve(elf_path, argv, envp));
  }*/
  else {
    return -LINUX_ENOEXEC;                  /* unsupported file type */
  }

  platform_free_filemapping(data, data_handle, size);
  proc->mm->current_brk = proc->mm->start_brk;

  return 0;
}

