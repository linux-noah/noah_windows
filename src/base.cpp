#include <cstdlib>
#include <cstring>
#include <cassert>

#include "common.h"
#include "noah.h"
#include "vm.h"
#include "linux/errno.h"

DEFINE_SYSCALL(unimplemented)
{
  uint64_t rax;

  read_register(VMM_X64_RAX, &rax);

  warnk("unimplemented syscall: %lld\n", rax);
  return -LINUX_ENOSYS;
}

#include "syscall.h"

#define _sys_unimplemented __ignore_me__
#define SYSCALL(n, name) uint64_t _sys_##name(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
SYSCALLS
#undef SYSCALL
#undef _sys_unimplemented

sc_handler_t sc_handler_table[NR_SYSCALLS] = {
#define SYSCALL(n, name) (sc_handler_t) _sys_##name,
  SYSCALLS
#undef SYSCALL
};

char *sc_name_table[NR_SYSCALLS] = {
#define SYSCALL(n, name) #name,
  SYSCALLS
#undef SYSCALL
};

#define DEFINE_NOT_IMPLEMENTED_SYSCALL(name)      \
  DEFINE_SYSCALL(name)                            \
  {                                               \
    return -LINUX_ENOSYS;                         \
  }

